rule sig_20151211_3611a8040551756b12d12b86db17f56c {
  meta:
    description = "datamaliciousorder - file 20151211_3611a8040551756b12d12b86db17f56c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d20fc1dd29ebe4dee656b65b7a137ab8babd1f4c6e40cd85bc0453cc93e0d0a3"

  strings:
    $s1  = "function KcUcnWl(ODsxAKXocpGFjNwJgnsceCvcWqSvMQIQflOs) {return !isNaN(parseFloat(ODsxAKXocpGFjNwJgnsceCvcWqSvMQIQflOs)) && isFin" ascii
    $s2  = "function KcUcnWl(ODsxAKXocpGFjNwJgnsceCvcWqSvMQIQflOs) {return !isNaN(parseFloat(ODsxAKXocpGFjNwJgnsceCvcWqSvMQIQflOs)) && isFin" ascii
    $s3  = "var G=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"34\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s4  = "function zMRgHlMSQWg(pLENonMT,bxdvRL){return pLENonMT.split(bxdvRL)}" fullword ascii
    $s5  = "var m=new Array(\"2f\",\"2a\",\"2a\",\"2f\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s6  = "function kLRwhqLljYjGJJNZs(NdjPQ){ftdVyBunZoS= '';SBLAXiXPLkp=(-645+645)/161; while(true){if(SBLAXiXPLkp >= (663+261)/462)break;" ascii
    $s7  = "PMZfCSJQL[SBLAXiXPLkp]=(-531+531)/420; while(true) { if(PMZfCSJQL[SBLAXiXPLkp] > NdjPQ[SBLAXiXPLkp].length-(260+17)/277) { break" ascii
    $s8  = "var G=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"34\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = "}SBLAXiXPLkp++;} return ftdVyBunZoS}" fullword ascii
    $s10 = "function UYoZDpOqsiOvseRVEonVkrXBRyZbOrkxiOOJUFSYTdNObxIsvAcidM(KNnPzOjaXgQLp,rOrVTeyuhvBSAi){ return Dpipq[bEMJe(KNnPzOjaXgQLp[" ascii
    $s11 = "function bEMJe(MtIwHxgSohC,qyTyoVqxHkUJx,NWaYVhcC){ABuG=parseInt(MtIwHxgSohC,qyTyoVqxHkUJx);enfir=ABuG.toString(NWaYVhcC);return" ascii
    $s12 = " enfir;}function tXRpFqMXTBJDyPF(CZflSyIWMGaQWcLPC){eval(CZflSyIWMGaQWcLPC)}" fullword ascii
    $s13 = "function UYoZDpOqsiOvseRVEonVkrXBRyZbOrkxiOOJUFSYTdNObxIsvAcidM(KNnPzOjaXgQLp,rOrVTeyuhvBSAi){ return Dpipq[bEMJe(KNnPzOjaXgQLp[" ascii
    $s14 = "function bEMJe(MtIwHxgSohC,qyTyoVqxHkUJx,NWaYVhcC){ABuG=parseInt(MtIwHxgSohC,qyTyoVqxHkUJx);enfir=ABuG.toString(NWaYVhcC);return" ascii
    $s15 = "var m=new Array(\"2f\",\"2a\",\"2a\",\"2f\",\"2c\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"59\",\"" ascii
    $s16 = "function kLRwhqLljYjGJJNZs(NdjPQ){ftdVyBunZoS= '';SBLAXiXPLkp=(-645+645)/161; while(true){if(SBLAXiXPLkp >= (663+261)/462)break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}