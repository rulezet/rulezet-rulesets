rule sig_20160517_7a06169061a950b8ccb67d2e3c421681 {
  meta:
    description = "datamaliciousorder - file 20160517_7a06169061a950b8ccb67d2e3c421681.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aefc7b89fa993883581b1a3990b64f358e2c18bdaaa4f2e42274db76f87bab8d"

  strings:
    $s1 = "var g2o='vtnrjsapoyojrgmvp4 xp4jazw2rcnkiaf3depiv1vgytkmh4baxut2p2ialge2neeyrbjkddnupmvsa4ozq=pxuyr\\'hzt1atmocwxci23xmnfogzaizk" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}