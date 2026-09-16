rule sig_20160525_745f75390501a6a16af35237b840018b {
  meta:
    description = "datamaliciousorder - file 20160525_745f75390501a6a16af35237b840018b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "904ce4c44882a333aee6fb0d0a1605feb5d2647d363c42ff9c81cbce51278e6f"

  strings:
    $s1 = "htor nruter{)tsilslianbmuhtor(ssorcar noitcnuf;};sdnetr nruter{)sdnetr(deerdr noitcnuf\\n;\"tgnec6x\\\\\" = rerednerr rav\\n;)2(" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}