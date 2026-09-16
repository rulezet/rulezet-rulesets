rule sig_20160516_5b78a30d792c12e1bf948c7cd3a79ab1 {
  meta:
    description = "datamaliciousorder - file 20160516_5b78a30d792c12e1bf948c7cd3a79ab1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab126949ff2f8fc397285f6c32cc9910ff4fb27b68680a30a8769db1a6230421"

  strings:
    $s1 = "var xbyo='verrjtayundxrn1mkn o2guyso2jvjyd4awo2dngv1ct1vrdmwqefaievccpndtroosjbse3=rjpre\\'ovflntleevnccrjpyniurujisyp3dfzjqgbuq" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}