rule sig_20160527_c6d0df354d5be3b3854d20fdcfe2a953 {
  meta:
    description = "datamaliciousorder - file 20160527_c6d0df354d5be3b3854d20fdcfe2a953.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32fab241969af121f29e330a501d43ea9b063180fa166f4357ba718671c13b91"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<axb2oJDIR6.length;i++)if(i%2==0)x.push(axb2oJDIR6[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}