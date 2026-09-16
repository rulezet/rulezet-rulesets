rule sig_20160526_d93ec2e66c94063db65600bcaf57473c {
  meta:
    description = "datamaliciousorder - file 20160526_d93ec2e66c94063db65600bcaf57473c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4f06946f6d21c9a5a6c08adfceeda8cbb47a0ad40429be86de5fc1c72f4e84b"

  strings:
    $s1 = "\\n\\r{\\n\\r)++1lVPPMYW ;]mNRWBEO + ))(};rEVFKTB nruter{)(iMGM noitcnuf([mUGW < 1lVPPMYW ;0 = 1lVPPMYW rav( rof\\n\\r\\n\\r;]5m" ascii
    $s2 = "\\n\\r;)(yarrA wen = 4xKCNGBX rav    \\n\\r   {\\n\\r)/*  yih vHr JQe */ wKIXQBL(0mDUQ noitcnuf\\n\\r\\n\\r\\n\\r;}\\n\\r;)4qGBY" ascii
    $s3 = "\\n\\r;)eslaf ,]]mNRWBEO + rEVFKTB[8gVNECSG % ++2uDKIUFA[8gVNECSG ,))(};9vMSD nruter{)(eEATRJZ noitcnuf((]tARO[kSYT" fullword ascii
    $s4 = "    var aolrQ4TpY = ';}\\n\\r;)(]fKUC[4oHPX    \\n\\r\\n\\r;)2 * 1 ,gDIQIKD(]sDBEZJZ + 0cXEERIV + )3wUEYJZQ(qSJZRQX[4oHPX    \\n" ascii
    $s5 = "\\n\\r;)(]))(};tARO nruter{)(dUAKRMT noitcnuf([5pAOOHGN" fullword ascii
    $s6 = "n\\r;\"p\" = sWFVEBE rav\\n\\r;\"nepo\" = tARO rav\\n\\r;\"TEG\" = 9vMSD rav\\n\\r;\"tgnel\" = rHMZWQF rav\\n\\r;\"h\" = 8hGPI r" ascii
    $s7 = " = oAST rav\\n\\r;\"FdaoL\" = 9gJSN rav\\n\\r;\"or\" = yBUVVQB rav\\n\\r;\"liFm\" = vRWQ rav\\n\\r;\"e\" = cTUYTPD rav\\n\\r;\"d" ascii
    $s8 = "JQUICQ(gVTQ(]2zQTLGMW + 4nXONXFQ[4oHPX    \\n\\r;)(]tARO[4oHPX    \\n\\r         ;/*  yih vHr JQe */ sNGY = ]0gMZD + lWUIAZI + l" ascii
    $s9 = "N[4oHPX    \\n\\r;)(]tARO[4oHPX    \\n\\r;/*  yih vHr JQe */ sNGY = ]0gMZD + )lWUIAZI(1kSJC + lXLEXHS[4oHPX    \\n\\r;8uSPA = ])" ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}