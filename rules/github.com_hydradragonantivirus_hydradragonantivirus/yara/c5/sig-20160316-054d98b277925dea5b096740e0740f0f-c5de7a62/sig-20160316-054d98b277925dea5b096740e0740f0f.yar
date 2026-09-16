rule sig_20160316_054d98b277925dea5b096740e0740f0f {
  meta:
    description = "datamaliciousorder - file 20160316_054d98b277925dea5b096740e0740f0f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5920a70e8c85da148f44f6bc9de5327ca4b113ae48b3a55bfd0ddac623cda562"

  strings:
    $s1 = "while (GIT[HpItoQxIdDjm + hNFPMpIOKt + RyIewOYKDHf + YByLNccGsKGf + yyV + rFss] < 4 ) {WScript[wujRBLHaYzZgI + SjSAkuI + PTltH +" ascii
    $s2 = "while (GIT[HpItoQxIdDjm + hNFPMpIOKt + RyIewOYKDHf + YByLNccGsKGf + yyV + rFss] < 4 ) {WScript[wujRBLHaYzZgI + SjSAkuI + PTltH +" ascii
    $s3 = "function JsLCuNEytBK(lCmtGdezW){Bkk[kNcgIBE + LWla](lCmtGdezW, 0, 0);}" fullword ascii
    $s4 = "MVszIT + MAAI + VCThVofddK + fkaekihClhzFU + QyFdlUmugpTLGg + SbW + BJFc + UoDleT + MjiiZJu + cCcthkD, false);" fullword ascii
    $s5 = "function RevpxvLcwKV(n){return mZYlcgZOjWLJ + NWcIVFAQFS + gAhERi + sZrHGBwDyFg + SVIWkAyUobzVx + kpTKtGOBH + bCd;}" fullword ascii
    $s6 = "var KNJqTuZof = new Date();" fullword ascii
    $s7 = "GIT[diwH + PIQaehoxbFd](ubyuhyEUbaI, ZAqdXOseQN + rByMGyjzFtCuq + eJGTAqphaukt + lZiEIzeCAc + yxi + ScAglyAUzp + CJPlSE + IDRPcy" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}