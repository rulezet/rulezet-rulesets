rule sig_20160526_ca1063f67193ae02b2d5e42f2b3c4f98 {
  meta:
    description = "datamaliciousorder - file 20160526_ca1063f67193ae02b2d5e42f2b3c4f98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5c52a412ad46e6bf1676e9844e8f99ba5bb78a8df7d865a9bf68500af58063e"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;])x" ascii
    $s2 = "\\n\\r;)yEAOUVQ(])iMAM(yKFJ[wVWSTAW" fullword ascii
    $s3 = "\\r;\"htgn\" = bVTO rav\\n\\r;\"nuR\" = iMAM rav;};yMKLZLG nruter{)yMKLZLG(yKFJ noitcnuf\\n\\r;\"eelS\" = bCCT rav\\n\\r;\"p\" =" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}