rule sig_20151209_64a24cdeb6fde0583f9a5979c4ff5866 {
  meta:
    description = "datamaliciousorder - file 20151209_64a24cdeb6fde0583f9a5979c4ff5866.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53f5c9ce996a3a6d2e618e8551329935244eb590a310fde2876bbd49cafd11fb"

  strings:
    $s1  = "function XRmbIMJ(cEwpIhzAOKVGHFJvSIgNIoeNFGnSOiWckaWE) {return !isNaN(parseFloat(cEwpIhzAOKVGHFJvSIgNIoeNFGnSOiWckaWE)) && isFin" ascii
    $s2  = "function XRmbIMJ(cEwpIhzAOKVGHFJvSIgNIoeNFGnSOiWckaWE) {return !isNaN(parseFloat(cEwpIhzAOKVGHFJvSIgNIoeNFGnSOiWckaWE)) && isFin" ascii
    $s3  = "WZtVaCwHt[qpfoblODvAx]=(-398+398)/432; while(true) { if(WZtVaCwHt[qpfoblODvAx] > TcxUx[qpfoblODvAx].length-(56+223)/279) { break" ascii
    $s4  = "function zNhPTMVsAmOcsMkPBYlJGvKyiZBeDMNbZjZwrHVZTnePAZHpQMtlAn(BNhcjtIKvttlV,RepMRAJXvtCibe){ return VfeoK[ZvYqm(BNhcjtIKvttlV[" ascii
    $s5  = "function zKuVKNGqdHYHpBpGe(TcxUx){iEqRcBukNpB= '';for(qpfoblODvAx=(-811+811)/179; qpfoblODvAx < (-249+709)/230; qpfoblODvAx++) {" ascii
    $s6  = "function zKuVKNGqdHYHpBpGe(TcxUx){iEqRcBukNpB= '';for(qpfoblODvAx=(-811+811)/179; qpfoblODvAx < (-249+709)/230; qpfoblODvAx++) {" ascii
    $s7  = "function zNhPTMVsAmOcsMkPBYlJGvKyiZBeDMNbZjZwrHVZTnePAZHpQMtlAn(BNhcjtIKvttlV,RepMRAJXvtCibe){ return VfeoK[ZvYqm(BNhcjtIKvttlV[" ascii
    $s8  = "function ZvYqm(YrBQJtUKwcI,wqzPvHRqcvnPG,rTuTVnfP){Ugki=parseInt(YrBQJtUKwcI,wqzPvHRqcvnPG);rtdyC=Ugki.toString(rTuTVnfP);return" ascii
    $s9  = "function zEGENaYCMFI(cJhnQUnj,kFuQRF){return cJhnQUnj.split(kFuQRF)}" fullword ascii
    $s10 = "+;}} return iEqRcBukNpB}" fullword ascii
    $s11 = "function ZvYqm(YrBQJtUKwcI,wqzPvHRqcvnPG,rTuTVnfP){Ugki=parseInt(YrBQJtUKwcI,wqzPvHRqcvnPG);rtdyC=Ugki.toString(rTuTVnfP);return" ascii
    $s12 = " rtdyC;}function JwexjYVbythbAyM(MPhfpiXMdWiDBXGWm){eval(MPhfpiXMdWiDBXGWm)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}