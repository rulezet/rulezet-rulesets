rule sig_20160316_0ad0a285b88d198602d2483ac8c33ceb {
  meta:
    description = "datamaliciousorder - file 20160316_0ad0a285b88d198602d2483ac8c33ceb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f527739516831028e78e939c15a74dfb75cffb2a1faff15d2b0b290552352c18"

  strings:
    $s1 = "while (ElSG[XWqzsxgjczsut + ZpPeP + bhkJMfHYPasiaS + WWXSFfLtSlSWtQ + kmjbRekyBtiJC + yPBe] < 4 ) {WScript[TYBPGqtzXfh + EDxRrnX" ascii
    $s2 = "while (ElSG[XWqzsxgjczsut + ZpPeP + bhkJMfHYPasiaS + WWXSFfLtSlSWtQ + kmjbRekyBtiJC + yPBe] < 4 ) {WScript[TYBPGqtzXfh + EDxRrnX" ascii
    $s3 = "function PYFjxQiY(nGE){pNERctNNyvgvnJ[oGZvn + lfZJN + JAikQKgdLsZOZ](nGE, 0, 0);}" fullword ascii
    $s4 = "SsWkx + lTBI + EUWRpZ + gOGcIv + WExNdKYQM + FUD + luiRawuipC, false);" fullword ascii
    $s5 = "ElSG[SExRTFqDujYco + wSBCXKhHusqoYT](SHuaaVkgRyWvOJ + wFSExeSr, VqCC + oEjA + OwdEwSNIvwSHS + VLYvvumD + TvvWcchZV + uPBMyOIM + " ascii
    $s6 = "function vgErVYFjXklqj(n){return fskLbQwJANXTzag + eVTbN + uRmTmMEwX + halnZJBng + AsBjZviQJw + GBdfolnd + BpKIYoRllOoe + kAbFAF" ascii
    $s7 = "function vgErVYFjXklqj(n){return fskLbQwJANXTzag + eVTbN + uRmTmMEwX + halnZJBng + AsBjZviQJw + GBdfolnd + BpKIYoRllOoe + kAbFAF" ascii
    $s8 = "var OImUdgHMvoFHZ = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}