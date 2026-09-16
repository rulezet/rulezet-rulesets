rule sig_20151209_2c5f4e15fcd4bb6fe6035d9e9645c90e {
  meta:
    description = "datamaliciousorder - file 20151209_2c5f4e15fcd4bb6fe6035d9e9645c90e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6795831eff3aee4021e8e2b587091e410b355dad3d2f0fdc5bb9738bfb1a5d9"

  strings:
    $s1  = "function BZvlRJA(slgLiRdMPwlnWyNmWxpNLTNrpRqBWrclpYqg) {return !isNaN(parseFloat(slgLiRdMPwlnWyNmWxpNLTNrpRqBWrclpYqg)) && isFin" ascii
    $s2  = "function BZvlRJA(slgLiRdMPwlnWyNmWxpNLTNrpRqBWrclpYqg) {return !isNaN(parseFloat(slgLiRdMPwlnWyNmWxpNLTNrpRqBWrclpYqg)) && isFin" ascii
    $s3  = "function gPiSIIAqrabfoSvQp(Udiyg){SPJWoPWQpYb= '';for(KDNstqeucOE=(-197+197)/368; KDNstqeucOE < (193+645)/419; KDNstqeucOE++) {Y" ascii
    $s4  = "function kKyRNChCrpo(vKgbqcru,mZDCkE){return vKgbqcru.split(mZDCkE)}" fullword ascii
    $s5  = "function xUpgK(DmoCxmPOMpK,ZMSolQOMnGqWv,jkCQBIYW){bNeg=parseInt(DmoCxmPOMpK,ZMSolQOMnGqWv);mqfIc=bNeg.toString(jkCQBIYW);return" ascii
    $s6  = ";}} return SPJWoPWQpYb}" fullword ascii
    $s7  = "KDqvurEE[KDNstqeucOE]=(-436+436)/974; while(true) { if(YKDqvurEE[KDNstqeucOE] > Udiyg[KDNstqeucOE].length-(-155+904)/749) { brea" ascii
    $s8  = "function xUpgK(DmoCxmPOMpK,ZMSolQOMnGqWv,jkCQBIYW){bNeg=parseInt(DmoCxmPOMpK,ZMSolQOMnGqWv);mqfIc=bNeg.toString(jkCQBIYW);return" ascii
    $s9  = " mqfIc;}function qwghnqLUIKCJqQV(PbpCZriRvSVLotyWC){eval(PbpCZriRvSVLotyWC)}" fullword ascii
    $s10 = "function ammtIsCaCUQObrcjyhCZCdiUiOvGjeqXUOONWsstzqjOzgiVfrujXD(mwIUmoJiKkoSO,awgaAiHiZtcMEi){ return ppEwV[xUpgK(mwIUmoJiKkoSO[" ascii
    $s11 = "function gPiSIIAqrabfoSvQp(Udiyg){SPJWoPWQpYb= '';for(KDNstqeucOE=(-197+197)/368; KDNstqeucOE < (193+645)/419; KDNstqeucOE++) {Y" ascii
    $s12 = "function ammtIsCaCUQObrcjyhCZCdiUiOvGjeqXUOONWsstzqjOzgiVfrujXD(mwIUmoJiKkoSO,awgaAiHiZtcMEi){ return ppEwV[xUpgK(mwIUmoJiKkoSO[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}