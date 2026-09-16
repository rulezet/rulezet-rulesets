rule sig_20160525_73fbfeac4b7a44e7a310b6b0e95ea372 {
  meta:
    description = "datamaliciousorder - file 20160525_73fbfeac4b7a44e7a310b6b0e95ea372.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae6c7b05bb60ad061261566574be15a585826e23a273c6a68fb67d0d2974e113"

  strings:
    $s1 = "nruter{)(tsilslianbmuhtoh noitcnuf( + tsilslianbmuhtog + ssorcag + sdnetg[tpircSW = gsmb rav    \\n{\\n)ima ,tsilslianbmuhtoa(su" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}