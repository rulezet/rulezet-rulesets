rule sig_20151209_e23d20a0b895dfa6104159ef5decd2e5 {
  meta:
    description = "datamaliciousorder - file 20151209_e23d20a0b895dfa6104159ef5decd2e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "167da84979ba547c7cffc4ae75f0e8a8365a8e29b7e558446d4b42c823548cd2"

  strings:
    $s1  = ";}} return EqjkojavIhV}" fullword ascii
    $s2  = "function urtRT(BcSaVhdhCpf,iwKHTQdnZWhGO,PzjgJkUz){oSlK=parseInt(BcSaVhdhCpf,iwKHTQdnZWhGO);uBcKx=oSlK.toString(PzjgJkUz);return" ascii
    $s3  = "function urtRT(BcSaVhdhCpf,iwKHTQdnZWhGO,PzjgJkUz){oSlK=parseInt(BcSaVhdhCpf,iwKHTQdnZWhGO);uBcKx=oSlK.toString(PzjgJkUz);return" ascii
    $s4  = "function aMTbtHQKXDWLmiCBo(VImeB){EqjkojavIhV= '';for(vhvvqsBEYLG=(-981+981)/457; vhvvqsBEYLG < (1586+320)/953; vhvvqsBEYLG++) {" ascii
    $s5  = "function aMTbtHQKXDWLmiCBo(VImeB){EqjkojavIhV= '';for(vhvvqsBEYLG=(-981+981)/457; vhvvqsBEYLG < (1586+320)/953; vhvvqsBEYLG++) {" ascii
    $s6  = "EbMyaRftz[vhvvqsBEYLG]=(-15+15)/234; while(true) { if(EbMyaRftz[vhvvqsBEYLG] > VImeB[vhvvqsBEYLG].length-(480+417)/897) { break;" ascii
    $s7  = " uBcKx;}function zpaYiQARumnnrvd(XmBruikGrRvEsQIJw){eval(XmBruikGrRvEsQIJw)}" fullword ascii
    $s8  = "function lKBqnmwwhzCCjKjIRJBqDQYelnnauWtNWnJEtWQiOMFxoMNTVFcmGw(zOOMBMfGKbVRf,IiAQmleRxkOOON){ return TAxes[urtRT(zOOMBMfGKbVRf[" ascii
    $s9  = "function lKBqnmwwhzCCjKjIRJBqDQYelnnauWtNWnJEtWQiOMFxoMNTVFcmGw(zOOMBMfGKbVRf,IiAQmleRxkOOON){ return TAxes[urtRT(zOOMBMfGKbVRf[" ascii
    $s10 = "function qIqzEXeJGBA(eUcoahTw,TYyNyP){return eUcoahTw.split(TYyNyP)}" fullword ascii
    $s11 = "Axes[83]='S';TAxes[84]='T';TAxes[85]='U';TAxes[86]='V';TAxes[87]='W';TAxes[88]='X';TAxes[89]='Y';TAxes[90]='Z';TAxes[91]='[';TAx" ascii
    $s12 = "function DRJhBjD(mAviLcvzXYNXPKWGIDYcAgnKlFPGNhVcHRXM) {return !isNaN(parseFloat(mAviLcvzXYNXPKWGIDYcAgnKlFPGNhVcHRXM)) && isFin" ascii
    $s13 = "function DRJhBjD(mAviLcvzXYNXPKWGIDYcAgnKlFPGNhVcHRXM) {return !isNaN(parseFloat(mAviLcvzXYNXPKWGIDYcAgnKlFPGNhVcHRXM)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}