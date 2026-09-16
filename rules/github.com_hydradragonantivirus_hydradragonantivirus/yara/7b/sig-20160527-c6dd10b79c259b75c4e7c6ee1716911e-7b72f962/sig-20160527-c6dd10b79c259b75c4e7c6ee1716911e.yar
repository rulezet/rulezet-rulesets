rule sig_20160527_c6dd10b79c259b75c4e7c6ee1716911e {
  meta:
    description = "datamaliciousorder - file 20160527_c6dd10b79c259b75c4e7c6ee1716911e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e63dc0cadc9f66c99d8635dae8b606fb1513ab9ce4bedce8caea9dc5464e474f"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aeIR6oKF.length;i++)if(i%2==0)x.push(aeIR6oKF[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}