rule sig_20151211_2a0dcb74816f6de192bf4f117f938329 {
  meta:
    description = "datamaliciousorder - file 20151211_2a0dcb74816f6de192bf4f117f938329.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a155d64e8dd74ffd66c3dd21112bd4375deac0d658d9af5c447eddeb0c13a36f"

  strings:
    $s1  = "function nKGinyi(hOMHaXVRlxWSnQVJxMgetjnLmijuWOzMamec) {return !isNaN(parseFloat(hOMHaXVRlxWSnQVJxMgetjnLmijuWOzMamec)) && isFin" ascii
    $s2  = "function nKGinyi(hOMHaXVRlxWSnQVJxMgetjnLmijuWOzMamec) {return !isNaN(parseFloat(hOMHaXVRlxWSnQVJxMgetjnLmijuWOzMamec)) && isFin" ascii
    $s3  = " qcbjE;}function JkedFZGeAxpCbxD(jxtlkyfMUCEzRtjVL){eval(jxtlkyfMUCEzRtjVL)}" fullword ascii
    $s4  = "function HkyaOsIqgXr(yVlGLYkw,euovfV){return yVlGLYkw.split(euovfV)}" fullword ascii
    $s5  = "function JiIwbuuSsJwJXftuPCeVzpoythKOgZFzobTxGYrXtATvbJZmLDXICM(ZsQGRDSDHLTFT,hwPjjEDcBuLwle){ return lMcZu[DaObu(ZsQGRDSDHLTFT[" ascii
    $s6  = "function xeLNmrJjBrzVyaFqo(cKQeG){drRGqKPKPJK= '';jNNExhgqNjN=(-255+255)/635; while(true){if(jNNExhgqNjN >= (1273+713)/993)break" ascii
    $s7  = "var y=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3k\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s8  = "var w=new Array(\"27\",\"2e\",\"2d\",\"28\",\"2e\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s9  = "var y=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3k\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "function JiIwbuuSsJwJXftuPCeVzpoythKOgZFzobTxGYrXtATvbJZmLDXICM(ZsQGRDSDHLTFT,hwPjjEDcBuLwle){ return lMcZu[DaObu(ZsQGRDSDHLTFT[" ascii
    $s11 = "function xeLNmrJjBrzVyaFqo(cKQeG){drRGqKPKPJK= '';jNNExhgqNjN=(-255+255)/635; while(true){if(jNNExhgqNjN >= (1273+713)/993)break" ascii
    $s12 = ";EWvYFFoms[jNNExhgqNjN]=(-435+435)/857; while(true) { if(EWvYFFoms[jNNExhgqNjN] > cKQeG[jNNExhgqNjN].length-(-678+758)/80) { bre" ascii
    $s13 = "var w=new Array(\"27\",\"2e\",\"2d\",\"28\",\"2e\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s14 = "N]++;}jNNExhgqNjN++;} return drRGqKPKPJK}" fullword ascii
    $s15 = "function DaObu(Jdgsxodrilj,SmCdjuBOqcccA,YxlzErJL){JFYM=parseInt(Jdgsxodrilj,SmCdjuBOqcccA);qcbjE=JFYM.toString(YxlzErJL);return" ascii
    $s16 = "function DaObu(Jdgsxodrilj,SmCdjuBOqcccA,YxlzErJL){JFYM=parseInt(Jdgsxodrilj,SmCdjuBOqcccA);qcbjE=JFYM.toString(YxlzErJL);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}