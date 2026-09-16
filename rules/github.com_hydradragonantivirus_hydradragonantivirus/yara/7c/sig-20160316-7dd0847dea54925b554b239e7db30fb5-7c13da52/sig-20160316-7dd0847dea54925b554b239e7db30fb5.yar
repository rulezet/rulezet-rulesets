rule sig_20160316_7dd0847dea54925b554b239e7db30fb5 {
  meta:
    description = "datamaliciousorder - file 20160316_7dd0847dea54925b554b239e7db30fb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09cb75f71105bafc9cb0c592ecf26a9c6b25e40feeaa0338d1dbecf88dfdea13"

  strings:
    $s1 = "while (XdLtxN[KSFa + wsqSZo + sWzFzPCxzHTBGRC + lVaCgBTzsGOX + RAmiYqPr] < 4 ) {WScript[BLkvgl + haOTlQ](1000)};" fullword ascii
    $s2 = "fCkY + jRTZw, false);" fullword ascii
    $s3 = "XdLtxN[PVjlhJpAKx + YrpzAjxyyBakw](hdwEKJhlVUcM + whgHt, IvjbdaFJACrG + tyoZfoFnakV + YqoqjlgGfEiGs + aCb + xhtlWvSvjqYAN + PnQT" ascii
    $s4 = "function mCoYmazkGAooza(n){return EELXzBOhszOjN + WAkyMH + sTRCHgmhPSe + TayJPB + iMTOvHPZaCFiVr + mRAoaOwQbM + BHTgyJJBHl + IXG" ascii
    $s5 = "function mCoYmazkGAooza(n){return EELXzBOhszOjN + WAkyMH + sTRCHgmhPSe + TayJPB + iMTOvHPZaCFiVr + mRAoaOwQbM + BHTgyJJBHl + IXG" ascii
    $s6 = "var PnRin = new Date();" fullword ascii
    $s7 = "function LiVbRvkuMEhI(DsikxtbI){GDfzmQm[LlLMXIPqFL](DsikxtbI, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}