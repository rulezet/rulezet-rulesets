rule sig_20160527_ca82d5eea41a768bfc92257f8a807bd3 {
  meta:
    description = "datamaliciousorder - file 20160527_ca82d5eea41a768bfc92257f8a807bd3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf86ecf6e78301a4987e811dcca7ab3f7f69baa18a00486484c7750511253eb0"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<autcIydQk.length;i++)if(i%2==0)x.push(autcIydQk[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}