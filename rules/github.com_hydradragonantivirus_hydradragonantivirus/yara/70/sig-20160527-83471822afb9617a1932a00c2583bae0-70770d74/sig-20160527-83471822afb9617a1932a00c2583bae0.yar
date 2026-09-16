rule sig_20160527_83471822afb9617a1932a00c2583bae0 {
  meta:
    description = "datamaliciousorder - file 20160527_83471822afb9617a1932a00c2583bae0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66bc94a0c0aed658044cb22b3c67ed01c0c8b4f9e2e1d09fe46bcc2e615fdbe7"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<adRwiR.length;i++)if(i%2==0)x.push(adRwiR[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}