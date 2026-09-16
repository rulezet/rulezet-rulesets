rule sig_20160316_9e968ab2d730596c19a91f6c68ba1971 {
  meta:
    description = "datamaliciousorder - file 20160316_9e968ab2d730596c19a91f6c68ba1971.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0d48114510c6a2a596b74fb223b72aca2c931325a2ed6e61022a712741808fb"

  strings:
    $s1 = "while (feGAWzgI[ggWjobqLz + trVQMaOSqk + NtdKnYTKi + QBLZOU + tSliCifBoLvHc] < 4 ) {WScript[yxjrhSOUADTXV + TfrgGxwKty + OwVuFof" ascii
    $s2 = "while (feGAWzgI[ggWjobqLz + trVQMaOSqk + NtdKnYTKi + QBLZOU + tSliCifBoLvHc] < 4 ) {WScript[yxjrhSOUADTXV + TfrgGxwKty + OwVuFof" ascii
    $s3 = "function GGoRSCBSf(n){return SukqlkHGXtmhw + vSyrzdwKypU + RJreJwQUTooCluv + eRIhBtMBRcxbyEy + cSXLtT + VpTjspAKFarJonK + AAJN;}" ascii
    $s4 = "function XFJBbfxQfF(wEtdfZm){XykJU[xzg + NVgZ](wEtdfZm, 0, 0);}" fullword ascii
    $s5 = "feGAWzgI[rIDebM + nGFeTQCQK](GQUbR + FYLsXvBwoSCi, OrVBXGOzImccL + sNVlVPCop + guwDx + lxZNb + wEKzFcTTIU + XoZZLTcvxxnMWg + nqS" ascii
    $s6 = "thCSbJr + UbZGhVs + HKjhQGQdm + EDZ + uZG + KFPf + JYgQ, false);" fullword ascii
    $s7 = "var VFDNwM = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}