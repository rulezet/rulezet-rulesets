rule sig_20160525_29b1c189a16ad2d7c077ec1c4d018bb5 {
  meta:
    description = "datamaliciousorder - file 20160525_29b1c189a16ad2d7c077ec1c4d018bb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa04e815343dfff0922b096b6db1bbb2b4ea44926c77c454c4c0db97e3ddde1d"

  strings:
    $s1  = "function oCkzpkMSQ(zySuPbVJgixHW) {var IQsNwPdRgniuSxDjxl = StvaMaFEfSt.join(TUeeFPxiJQzPr[0]);var vEgHNRUEaOFFnVOSRMMtkIEj, slh" ascii
    $s2  = "MKwSFdoKdUaouyB += FGr(vEgHNRUEaOFFnVOSRMMtkIEj);else if (JUGsvqKgqgzsfN == (633 + Math.round((Math.pow(Math.sin(946), 2) + Math" ascii
    $s3  = "function pbWNxcDKPVzf(gQfuqEA,RoKTuovkgXHol){return gQfuqEA.charAt(RoKTuovkgXHol);}" fullword ascii
    $s4  = "function xFbcRMqUY(wOshNgzYgtsVPSAVkmU,oYjFFKBDNu,IXoUXcJVgLtKkZgJjKeIDnZ){return String.fromCharCode(wOshNgzYgtsVPSAVkmU,oYjFFK" ascii
    $s5  = "function FGr(AFBPRtEhTprpraUHB){return String.fromCharCode(AFBPRtEhTprpraUHB);}" fullword ascii
    $s6  = "ypUlizW < zySuPbVJgixHW.length);return abJnhTYkMKwSFdoKdUaouyB;}" fullword ascii
    $s7  = "function ooPDJwePkAdFwyIzRpBH(miEXEgRAbIiLySgfMUcl,HnMHUCXLntnFmclNuC){return miEXEgRAbIiLySgfMUcl.indexOf(HnMHUCXLntnFmclNuC);}" ascii
    $s8  = "function oCkzpkMSQ(zySuPbVJgixHW) {var IQsNwPdRgniuSxDjxl = StvaMaFEfSt.join(TUeeFPxiJQzPr[0]);var vEgHNRUEaOFFnVOSRMMtkIEj, slh" ascii
    $s9  = "se abJnhTYkMKwSFdoKdUaouyB += xFbcRMqUY(vEgHNRUEaOFFnVOSRMMtkIEj, slhvLhAsUnwmxBGLZgZusucT, UudweFiudbPJgXZ);} while (gXAHKpgtGs" ascii
    $s10 = "function VSVdIGlqxsU(WbRJrQuAapLUW,aKPSTFeItjL){return String.fromCharCode(WbRJrQuAapLUW,aKPSTFeItjL);}" fullword ascii
    $s11 = "function xFbcRMqUY(wOshNgzYgtsVPSAVkmU,oYjFFKBDNu,IXoUXcJVgLtKkZgJjKeIDnZ){return String.fromCharCode(wOshNgzYgtsVPSAVkmU,oYjFFK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}