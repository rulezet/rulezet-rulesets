rule sig_20151211_4cb8f955300ef03750c65f9a2ed43c7d {
  meta:
    description = "datamaliciousorder - file 20151211_4cb8f955300ef03750c65f9a2ed43c7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09f369554a54fc748b7c46fb96a6b608174d69ff4c7ae544e362a9aa3f576e84"

  strings:
    $s1  = "function CjjvOlt(PaAgdcondQaWbUfcpoYyyWrKgUqspSSsMKHZ) {return !isNaN(parseFloat(PaAgdcondQaWbUfcpoYyyWrKgUqspSSsMKHZ)) && isFin" ascii
    $s2  = "function CjjvOlt(PaAgdcondQaWbUfcpoYyyWrKgUqspSSsMKHZ) {return !isNaN(parseFloat(PaAgdcondQaWbUfcpoYyyWrKgUqspSSsMKHZ)) && isFin" ascii
    $s3  = "var h=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "var X=new Array(\"2b\",\"2a\",\"2a\",\"26\",\"2a\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s5  = "function xJirpaYBezA(QJQiutiR,UpYJyM){return QJQiutiR.split(UpYJyM)}" fullword ascii
    $s6  = "function VIRPyJNEkRUVPPgtt(XlkTu){FRxJHDppcDq= '';AXNMtHYydtN=(-643+643)/495; while(true){if(AXNMtHYydtN >= (306+88)/197)break;Y" ascii
    $s7  = "var X=new Array(\"2b\",\"2a\",\"2a\",\"26\",\"2a\",\"2a\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "function RWrja(NOoEmQxNPhO,xjGgynFKgZfpv,SAuaoepu){RzwW=parseInt(NOoEmQxNPhO,xjGgynFKgZfpv);gqNiS=RzwW.toString(SAuaoepu);return" ascii
    $s9  = "var h=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"41\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s10 = "KUGWiAXH[AXNMtHYydtN]=(-142+142)/415; while(true) { if(YKUGWiAXH[AXNMtHYydtN] > XlkTu[AXNMtHYydtN].length-(331+595)/926) { break" ascii
    $s11 = " gqNiS;}function SvVPUpskXAWzQTB(IYzXOVboXiOiFIZMF){eval(IYzXOVboXiOiFIZMF)}" fullword ascii
    $s12 = "+;}AXNMtHYydtN++;} return FRxJHDppcDq}" fullword ascii
    $s13 = "function VIRPyJNEkRUVPPgtt(XlkTu){FRxJHDppcDq= '';AXNMtHYydtN=(-643+643)/495; while(true){if(AXNMtHYydtN >= (306+88)/197)break;Y" ascii
    $s14 = "function RWrja(NOoEmQxNPhO,xjGgynFKgZfpv,SAuaoepu){RzwW=parseInt(NOoEmQxNPhO,xjGgynFKgZfpv);gqNiS=RzwW.toString(SAuaoepu);return" ascii
    $s15 = "function UpWnllLGrqUpGqqIxWzLlIIzgnvMPAksoKTVWyQIzKRiPFLioSeXTg(ANekuYHbsuHoJ,QnTUPrirBFnhQE){ return carMX[RWrja(ANekuYHbsuHoJ[" ascii
    $s16 = "function UpWnllLGrqUpGqqIxWzLlIIzgnvMPAksoKTVWyQIzKRiPFLioSeXTg(ANekuYHbsuHoJ,QnTUPrirBFnhQE){ return carMX[RWrja(ANekuYHbsuHoJ[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}