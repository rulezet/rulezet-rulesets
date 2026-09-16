rule sig_20160526_f6d2d5c2f31be25431c2ef07fd5d6397 {
  meta:
    description = "datamaliciousorder - file 20160526_f6d2d5c2f31be25431c2ef07fd5d6397.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d05076d7bb44f735ce2e57eda6ff17fec6242cd74c905138050536ef17ad2819"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]))" ascii
    $s2 = "r;\"ahC\" = lXLEXHS rav\\n\\r;\"esr\" = lWUIAZI rav\\n\\r;\"t\" = 0gMZD rav;};5uNNTINF nruter{)5uNNTINF(1kSJC noitcnuf\\n\\r;\"n" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}