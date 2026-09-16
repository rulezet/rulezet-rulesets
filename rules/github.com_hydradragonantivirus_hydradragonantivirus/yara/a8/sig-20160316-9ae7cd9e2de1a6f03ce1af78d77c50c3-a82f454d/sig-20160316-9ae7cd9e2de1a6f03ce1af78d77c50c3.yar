rule sig_20160316_9ae7cd9e2de1a6f03ce1af78d77c50c3 {
  meta:
    description = "datamaliciousorder - file 20160316_9ae7cd9e2de1a6f03ce1af78d77c50c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0443cda6e3a4444b80006438d64acd1cb84d13079b450a7739cf48dd7f6d7bc5"

  strings:
    $s1 = "while (HzgBeYCnctqlJGi[dsdAHSfpTTXclp + yzXafHrfEBBE + VOOaqPM + aBagXMhySzCLUuv + yBRYkiecfsG] < 4 ) {WScript[CinXfR + qSWnmNna" ascii
    $s2 = "while (HzgBeYCnctqlJGi[dsdAHSfpTTXclp + yzXafHrfEBBE + VOOaqPM + aBagXMhySzCLUuv + yBRYkiecfsG] < 4 ) {WScript[CinXfR + qSWnmNna" ascii
    $s3 = "xu + XWYqnG, false);" fullword ascii
    $s4 = "HzgBeYCnctqlJGi[rFdI + ohiLXuOuyFoFC](kbKiVCgqS, DFkCELyL + ItdwzWsxizytam + PDYulqwYBUGZK + zSPkZTaLZRLC + ZvthkXI + bacsVwtYf " ascii
    $s5 = "function kSABeRDEJQOGM(n){return ifztFdEoCqLb + zNE + UhJwaeIStSYlq + llIWo + ENuTL + qVHT;}" fullword ascii
    $s6 = "function VqmAgxEBVhtz(ZHvelaKxazwk){AVKNPIMsBmrlunK[YSiNKUnWoDmX + ZDATx](ZHvelaKxazwk, 0, 0);}" fullword ascii
    $s7 = "MzMfNFpko[ZUvBlCjg + YTtIax + RivKrtPnAZOyjM + taRt + wOAiU](YbPhSamJRb, 2 );" fullword ascii
    $s8 = "var taRt = \"oFi\";" fullword ascii
    $s9 = "var EXJEUP = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}