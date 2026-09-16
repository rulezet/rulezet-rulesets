rule sig_20151211_d1311282605bbb49aea62cd08ee287e5 {
  meta:
    description = "datamaliciousorder - file 20151211_d1311282605bbb49aea62cd08ee287e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "589c7445fa650683717c820386f4f30fa3e724c6e1ca1802f92929bc312ca631"

  strings:
    $s1  = "function VOklVXu(BCFwZQRGJtcvyhrnvKNXfeZhZHgMQnDxFcvk) {return !isNaN(parseFloat(BCFwZQRGJtcvyhrnvKNXfeZhZHgMQnDxFcvk)) && isFin" ascii
    $s2  = "function VOklVXu(BCFwZQRGJtcvyhrnvKNXfeZhZHgMQnDxFcvk) {return !isNaN(parseFloat(BCFwZQRGJtcvyhrnvKNXfeZhZHgMQnDxFcvk)) && isFin" ascii
    $s3  = "function uKxVw(dYWwByjFYnr,qkvRSEnBbVqQF,HrTBpaRB){VNRQ=parseInt(dYWwByjFYnr,qkvRSEnBbVqQF);oIaia=VNRQ.toString(HrTBpaRB);return" ascii
    $s4  = "function KgyCbXWrbXJ(DfNKDxrb,UiXCmI){return DfNKDxrb.split(UiXCmI)}" fullword ascii
    $s5  = "var v=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s6  = "var v=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"3c\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = "var n=new Array(\"2d\",\"2d\",\"2a\",\"2d\",\"2a\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "var n=new Array(\"2d\",\"2d\",\"2a\",\"2d\",\"2a\",\"2f\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s9  = "function uKxVw(dYWwByjFYnr,qkvRSEnBbVqQF,HrTBpaRB){VNRQ=parseInt(dYWwByjFYnr,qkvRSEnBbVqQF);oIaia=VNRQ.toString(HrTBpaRB);return" ascii
    $s10 = " oIaia;}function dwlwjmFeaCGIIRV(vlRTVDcszRnFrzfmq){eval(vlRTVDcszRnFrzfmq)}" fullword ascii
    $s11 = "function hIFdjfWgcTfaLoqsKDAceDcGbxdKWjKPFKHJmikSfOdcbsrqxaTfzV(bsYxDQbGOHHjz,InBCecOfjQzJyv){ return jQvLh[uKxVw(bsYxDQbGOHHjz[" ascii
    $s12 = "function hIFdjfWgcTfaLoqsKDAceDcGbxdKWjKPFKHJmikSfOdcbsrqxaTfzV(bsYxDQbGOHHjz,InBCecOfjQzJyv){ return jQvLh[uKxVw(bsYxDQbGOHHjz[" ascii
    $s13 = "}qfBopcbcatE++;} return oNYJeGnjtHm}" fullword ascii
    $s14 = "function KzXqZItDXCzzckMHO(tZYmJ){oNYJeGnjtHm= '';qfBopcbcatE=(-7+7)/620; while(true){if(qfBopcbcatE >= (358+866)/612)break;JqZe" ascii
    $s15 = "function KzXqZItDXCzzckMHO(tZYmJ){oNYJeGnjtHm= '';qfBopcbcatE=(-7+7)/620; while(true){if(qfBopcbcatE >= (358+866)/612)break;JqZe" ascii
    $s16 = "KVBVK[qfBopcbcatE]=(-340+340)/174; while(true) { if(JqZeKVBVK[qfBopcbcatE] > tZYmJ[qfBopcbcatE].length-(-446+842)/396) { break; " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}