rule sig_20160316_702c52ad6e71b5697bb6f8a52bc976a1 {
  meta:
    description = "datamaliciousorder - file 20160316_702c52ad6e71b5697bb6f8a52bc976a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eebc05d114c44b6753e170cc7b8898962fb14b4a9ec9ae68a09460f139e8d6a8"

  strings:
    $s1 = "while (cHTGIBxcavKkSq[ixYSFrgxDolb + rOYsnVGWy + msg + tmJIcjxJrIU + Pyjn + PRBQsyBdTuBxrQ] < 4 ) {WScript[lWsA + MdbFQ + CiZEDi" ascii
    $s2 = "while (cHTGIBxcavKkSq[ixYSFrgxDolb + rOYsnVGWy + msg + tmJIcjxJrIU + Pyjn + PRBQsyBdTuBxrQ] < 4 ) {WScript[lWsA + MdbFQ + CiZEDi" ascii
    $s3 = "cHTGIBxcavKkSq[PyOjOJIhTmgcrBg + QoPFrscymv + RUuUkOn](brXNYvBipgaOxwT, qsLVfqKKYJeZJGa + wXEmKIzIFKcoy + ZhqJWMTPviLSVl + RUhSp" ascii
    $s4 = "function fXoGNASlrY(n){return dSeqs + akvoPcBzXxOjDKP + xPZcZQVAK + hzENgHHDnCJGtPb + lEIHDriIyrB + cmbujF + cRRly + nUyvvEI + R" ascii
    $s5 = "htwZpyfHRw + VFd, false);" fullword ascii
    $s6 = "function fXoGNASlrY(n){return dSeqs + akvoPcBzXxOjDKP + xPZcZQVAK + hzENgHHDnCJGtPb + lEIHDriIyrB + cmbujF + cRRly + nUyvvEI + R" ascii
    $s7 = "function BqaU(KdRZWyzeQwjFvcm){SDDFJw[FzU + mAvi](KdRZWyzeQwjFvcm, 0, 0);}" fullword ascii
    $s8 = "var CjNVxOgx = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}