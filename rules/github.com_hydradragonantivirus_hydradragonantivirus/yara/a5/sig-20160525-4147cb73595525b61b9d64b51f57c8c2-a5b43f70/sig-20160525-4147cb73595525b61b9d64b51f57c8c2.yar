rule sig_20160525_4147cb73595525b61b9d64b51f57c8c2 {
  meta:
    description = "datamaliciousorder - file 20160525_4147cb73595525b61b9d64b51f57c8c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e28e5aa67e390a099c25d186d6da70346e1c0aa7fc33ecef6f8ade1ce7734b84"

  strings:
    $s1 = "lcitrapf + gsmf + eixodf + ime + ))(};rerednere nruter{)(keppelf noitcnuf([tpircSW = eixodb rav    \\n{\\n)rerednera ,ssorcaa(su" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}