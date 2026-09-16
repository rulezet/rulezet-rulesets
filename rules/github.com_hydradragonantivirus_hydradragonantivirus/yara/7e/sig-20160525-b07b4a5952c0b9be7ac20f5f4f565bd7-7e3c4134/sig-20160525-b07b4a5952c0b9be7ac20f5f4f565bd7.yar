rule sig_20160525_b07b4a5952c0b9be7ac20f5f4f565bd7 {
  meta:
    description = "datamaliciousorder - file 20160525_b07b4a5952c0b9be7ac20f5f4f565bd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1e536c625f1ffc03d6d7b154561bdd7971556f3014a341b38273aea964ee636"

  strings:
    $s1 = "dark(])suidarelcitrapf(mf + gsmf + eixodf + ime[tpircSW = eixodb rav    \\n{\\n)rerednera ,ssorcaa(suidarelcitrap noitcnuf\\n\\n" ascii
    $s2 = "sillocu rav\\n;\"ge6x\\\\el\" = mu rav\\n;\"h47x\\\\\" = gedotdaru rav\\n;\"ec6x\\\\\" = keppelu rav\\n;\"86x\\\\tgn\" = ecapset" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}