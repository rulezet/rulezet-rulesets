rule sig_20151215_454027e7334cc1fff6195097d2c75842 {
  meta:
    description = "datamaliciousorder - file 20151215_454027e7334cc1fff6195097d2c75842.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c236d5ecaa39843524a22354022466c8f1006f3e372f3eab2aa1b8c11fb6199e"

  strings:
    $s1  = "Math.pow(Math.cos(700), 2) - 1)); while(true) { if(sUhULcyuZ[TMPsfeditWh] > ndVqc[TMPsfeditWh].length-(-9+543)/534) { break; } i" ascii
    $s2  = "ow(Math.cos(502), 2) - 1)));} sUhULcyuZ[TMPsfeditWh]++;}} return QRXyeqsRpJw}" fullword ascii
    $s3  = "function qyoHgfzRDiNcVCHmP(ndVqc){QRXyeqsRpJw= J[1820];for(TMPsfeditWh=Math.round((Math.pow(Math.sin(251), 2) + Math.pow(Math.co" ascii
    $s4  = "function qyoHgfzRDiNcVCHmP(ndVqc){QRXyeqsRpJw= J[1820];for(TMPsfeditWh=Math.round((Math.pow(Math.sin(251), 2) + Math.pow(Math.co" ascii
    $s5  = "uiKA)) {return (String.fromCharCode(gDXuyzjoXUcuuiKA) + String.fromCharCode((54109+991)/950));}}" fullword ascii
    $s6  = "function S(fnFjkABUUlIM,WwAkIWnFAeKNYv){fnFjkABUUlIM.push(WwAkIWnFAeKNYv);}function W2(gDXuyzjoXUcuuiKA){if(qQauYNv(gDXuyzjoXUcu" ascii
    $s7  = "function qQauYNv(pqSlWtQPgcpHDpjFRHxTluuKkTbmKYKSyUAW) {return !isNaN(parseFloat(pqSlWtQPgcpHDpjFRHxTluuKkTbmKYKSyUAW)) && isFin" ascii
    $s8  = "function qQauYNv(pqSlWtQPgcpHDpjFRHxTluuKkTbmKYKSyUAW) {return !isNaN(parseFloat(pqSlWtQPgcpHDpjFRHxTluuKkTbmKYKSyUAW)) && isFin" ascii
    $s9  = "function PwCeYOlCVavQmvW(SBNNDwUVaXVuNFCSN){eval(SBNNDwUVaXVuNFCSN)}" fullword ascii
    $s10 = "function S(fnFjkABUUlIM,WwAkIWnFAeKNYv){fnFjkABUUlIM.push(WwAkIWnFAeKNYv);}function W2(gDXuyzjoXUcuuiKA){if(qQauYNv(gDXuyzjoXUcu" ascii
    $s11 = "function WvHGY(kUGaFplSVUq,hzdtqXesJKjhb,kwLNDUVG){lOtF=parseInt(kUGaFplSVUq,hzdtqXesJKjhb);AbCjh=lOtF.toString(kwLNDUVG);return" ascii
    $s12 = " AbCjh;}function PwCeYOlCVavQmvW(SBNNDwUVaXVuNFCSN,ZeSUitAuCWmSDAFZYNwlGywZFUwHvgsDJe,zGQUZGEuoRHqdoJmgyDsUdFjvYxplPonhuV){eval(" ascii
    $s13 = "function WvHGY(kUGaFplSVUq,hzdtqXesJKjhb,kwLNDUVG){lOtF=parseInt(kUGaFplSVUq,hzdtqXesJKjhb);AbCjh=lOtF.toString(kwLNDUVG);return" ascii
    $s14 = "function xCvDOnfVNINzfOQdabCCUPxTYXjMyowpDcyZhVGBQJwPpfSBNKuoEA(hxgLKmNcZrFYc,JCiUQmwoPODZRY){ return qFIrsHb[uYLhIYSd[WvHGY(hxg" ascii
    $s15 = "function xCvDOnfVNINzfOQdabCCUPxTYXjMyowpDcyZhVGBQJwPpfSBNKuoEA(hxgLKmNcZrFYc,JCiUQmwoPODZRY){ return qFIrsHb[uYLhIYSd[WvHGY(hxg" ascii
    $s16 = "function JfdnHQwIkky(FDYpWsHK,QxFBLK){return FDYpWsHK.split(QxFBLK)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}