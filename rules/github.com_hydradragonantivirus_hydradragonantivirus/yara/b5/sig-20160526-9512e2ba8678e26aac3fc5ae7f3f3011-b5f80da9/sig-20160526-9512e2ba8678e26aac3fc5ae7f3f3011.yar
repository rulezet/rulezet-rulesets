rule sig_20160526_9512e2ba8678e26aac3fc5ae7f3f3011 {
  meta:
    description = "datamaliciousorder - file 20160526_9512e2ba8678e26aac3fc5ae7f3f3011.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fde892371ed40c6fc3b6f5a049c81bf7f852b26bb56c197d4d88e2558280a379"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])4" ascii
    $s2 = "\\n\\r;)yEAOUVQ(])iMAM(yKFJ[wVWSTAW" fullword ascii
    $s3 = "Y rav\\n\\r;\"el\" = 8aEXP rav\\n\\r;\"htgn\" = bVTO rav\\n\\r;\"nuR\" = iMAM rav;};yMKLZLG nruter{)yMKLZLG(yKFJ noitcnuf\\n\\r;" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}