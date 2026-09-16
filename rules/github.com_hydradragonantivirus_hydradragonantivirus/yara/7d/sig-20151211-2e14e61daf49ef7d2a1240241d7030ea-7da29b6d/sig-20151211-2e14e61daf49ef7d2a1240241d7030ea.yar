rule sig_20151211_2e14e61daf49ef7d2a1240241d7030ea {
  meta:
    description = "datamaliciousorder - file 20151211_2e14e61daf49ef7d2a1240241d7030ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a90be37101f03fa4293fb7d4b3d1203689feaaeb5b18b548b166fde7db45b4ca"

  strings:
    $s1  = "function izdaNpU(jfSsLRRqoygtgdFhoqKtaSInbNaTuJaZFCTG) {return !isNaN(parseFloat(jfSsLRRqoygtgdFhoqKtaSInbNaTuJaZFCTG)) && isFin" ascii
    $s2  = "function izdaNpU(jfSsLRRqoygtgdFhoqKtaSInbNaTuJaZFCTG) {return !isNaN(parseFloat(jfSsLRRqoygtgdFhoqKtaSInbNaTuJaZFCTG)) && isFin" ascii
    $s3  = "function fsmSzcwjgneZieMXO(ksMUf){qPNIXZkGFSw= '';kxeQzKMrxML=(-60+60)/636; while(true){if(kxeQzKMrxML >= (-208+386)/89)break;oY" ascii
    $s4  = "TAVvwxq[kxeQzKMrxML]=(-375+375)/614; while(true) { if(oYTAVvwxq[kxeQzKMrxML] > ksMUf[kxeQzKMrxML].length-(-137+783)/646) { break" ascii
    $s5  = "function Wjjng(VXgNmzlbGpy,PxChFWIzpApgT,BAnzhNEa){JKjd=parseInt(VXgNmzlbGpy,PxChFWIzpApgT);YHVPP=JKjd.toString(BAnzhNEa);return" ascii
    $s6  = "function tnjzcNWpPDumjJcBHqOizkcIntUXCFcZNoOPwTxheNyvhtlagffjQM(vhkdbqTjVtxir,wXhlgCeFsWSfJN){ return rtRPQ[Wjjng(vhkdbqTjVtxir[" ascii
    $s7  = " YHVPP;}function OudapCBwtrOkYmC(SfoxnYlXZiGutnRxI){eval(SfoxnYlXZiGutnRxI)}" fullword ascii
    $s8  = "++;}kxeQzKMrxML++;} return qPNIXZkGFSw}" fullword ascii
    $s9  = "function tnjzcNWpPDumjJcBHqOizkcIntUXCFcZNoOPwTxheNyvhtlagffjQM(vhkdbqTjVtxir,wXhlgCeFsWSfJN){ return rtRPQ[Wjjng(vhkdbqTjVtxir[" ascii
    $s10 = "var L=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"53\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s11 = "function fsmSzcwjgneZieMXO(ksMUf){qPNIXZkGFSw= '';kxeQzKMrxML=(-60+60)/636; while(true){if(kxeQzKMrxML >= (-208+386)/89)break;oY" ascii
    $s12 = "var J=new Array(\"2d\",\"27\",\"2e\",\"2f\",\"2c\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s13 = "function Wjjng(VXgNmzlbGpy,PxChFWIzpApgT,BAnzhNEa){JKjd=parseInt(VXgNmzlbGpy,PxChFWIzpApgT);YHVPP=JKjd.toString(BAnzhNEa);return" ascii
    $s14 = "function wAAGEpGENgb(VlhMoZJv,mOHtUx){return VlhMoZJv.split(mOHtUx)}" fullword ascii
    $s15 = "var L=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"53\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s16 = "var J=new Array(\"2d\",\"27\",\"2e\",\"2f\",\"2c\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}