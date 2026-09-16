rule sig_20160526_751218dbc692c4648583e26785d6ced4 {
  meta:
    description = "datamaliciousorder - file 20160526_751218dbc692c4648583e26785d6ced4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79e3dd47d096ad7e97a7ddf7ecac07925c96bc4bcd1bfed7efaf6f5b7a96e34c"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])x" ascii
    $s2 = "\\n\\r;)yEAOUVQ(])iMAM(yKFJ[wVWSTAW" fullword ascii
    $s3 = "\"h\" = zYPY rav\\n\\r;\"el\" = 8aEXP rav\\n\\r;\"htgn\" = bVTO rav\\n\\r;\"nuR\" = iMAM rav;};yMKLZLG nruter{)yMKLZLG(yKFJ noit" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}