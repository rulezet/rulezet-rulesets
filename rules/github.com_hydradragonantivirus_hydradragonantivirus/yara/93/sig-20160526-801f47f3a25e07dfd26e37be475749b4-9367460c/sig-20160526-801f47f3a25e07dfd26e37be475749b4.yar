rule sig_20160526_801f47f3a25e07dfd26e37be475749b4 {
  meta:
    description = "datamaliciousorder - file 20160526_801f47f3a25e07dfd26e37be475749b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cf9dc45978b7253c6aeb6275dbab095b52c3cb0bbf7e86c4c93ef0d3afa9429"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])4" ascii
    $s2 = "\\n\\r;)yEAOUVQ(])iMAM(yKFJ[wVWSTAW" fullword ascii
    $s3 = "av\\n\\r;\"el\" = 8aEXP rav\\n\\r;\"htgn\" = bVTO rav\\n\\r;\"nuR\" = iMAM rav;};yMKLZLG nruter{)yMKLZLG(yKFJ noitcnuf\\n\\r;\"e" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}