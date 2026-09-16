rule sig_20160526_1339b08d2c302890287c2b27edbf5e31 {
  meta:
    description = "datamaliciousorder - file 20160526_1339b08d2c302890287c2b27edbf5e31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84f9af907497e0b3f48eeebb740ec4dd4de4a333a619e71a3084d85ac94b48e2"

  strings:
    $s1  = "\\n\\r;)]1lVPPMYW[mUGW(]nNKP + ))(};2gVBUIQD nruter{)(kAHTQGH noitcnuf( + )7kHYL(1iDED + yERD[tpircSW = kSYT rav" fullword ascii
    $s2  = "\\n\\r;)))(};1eYVM nruter{)(0cMCNKAG noitcnuf( + aXRNOSV + 8jBPZXGD + 3vQEY(]nNKP + )2gVBUIQD(9qNYX + 7kHYL + ))(};yERD nruter{)" ascii
    $s3  = "+ 7kHYL + yERD[tpircSW = wVWSTAW rav\\n\\r;]hPPMOEX + 7sSZO+))(};dHQVKVL nruter{)(yFRV noitcnuf(+lBHOBZI+))(};tKUP nruter{)(4eHU" ascii
    $s4  = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]))" ascii
    $s5  = "\\n\\r;)))(};1eYVM nruter{)(0cMCNKAG noitcnuf( + aXRNOSV + 8jBPZXGD + 3vQEY(]nNKP + )2gVBUIQD(9qNYX + 7kHYL + ))(};yERD nruter{)" ascii
    $s6  = "\\n\\r;)(yarrA wen = 4xKCNGBX rav    \\n\\r   {\\n\\r)/*  rvo gto UvC */ wKIXQBL(0mDUQ noitcnuf\\n\\r\\n\\r\\n\\r;}\\n\\r;)4qGBY" ascii
    $s7  = "    var aEhpBMq = ';}\\n\\r;)(]6pJEECRB + 6fDLJ[4oHPX    \\n\\r\\n\\r;)2 * 1 ,gDIQIKD(]bMPY + yYND + 9iBPM[4oHPX    \\n\\r;))6eJ" ascii
    $s8  = "};yERD nruter{)(nOYLWNX noitcnuf([tpircSW = 4oHPX rav    \\n\\r{\\n\\r)gDIQIKD(0zPVL noitcnuf\\n\\r\\n\\r\\n\\r;}\\n\\r};eslaf n" ascii
    $s9  = "PYH(uBEC noitcnuf\\n\\r;\".o\" = lBHOBZI rav\\n\\r;\"8/ku\" = dHQVKVL rav\\n\\r;\"ot4\" = 7sSZO rav\\n\\r;\"h\" = hPPMOEX rav\\n" ascii
    $s10 = "[4oHPX    \\n\\r;8uSPA = ]tDGI[4oHPX    \\n\\r;)1eYVM + aXRNOSV + 8jBPZXGD + 3vQEY(]nNKP + )2gVBUIQD(7qQWQ + 7kHYL + )yERD(4yESR" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}