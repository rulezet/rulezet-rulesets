rule sig_20160526_8b3ea772b10547e73a40fe7288c9c799 {
  meta:
    description = "datamaliciousorder - file 20160526_8b3ea772b10547e73a40fe7288c9c799.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfc8019c50d4c51f2c32d99248af3c313d1d09ba80a4c0e79a72e78150499e7a"

  strings:
    $s1  = "os(650), 2) - 1))-333)) eSGTGUQsXLQiyNB += Vb(raTkZriHoAJtWMTzjd);else if (gSEwzhUvhCEFZo == (303 + Math.round((Math.pow(Math.si" ascii
    $s2  = "n(644), 2) + Math.pow(Math.cos(644), 2) - 1))-239)) eSGTGUQsXLQiyNB += vXOsGv(raTkZriHoAJtWMTzjd, jSvAHKhli);else eSGTGUQsXLQiyN" ascii
    $s3  = "function OeIdQTkdsj(CCwrWFmvaIchq) {var XsfQczljeEpwbyofLU = BgoieauXlCvoGuVlPZ.join(vnlBuKs[0]);var raTkZriHoAJtWMTzjd, jSvAHKh" ascii
    $s4  = "function PuiKdufRtqE(nYhiGbwXlZhGDQCb,tgHIkzXcrpOlIFmn){return nYhiGbwXlZhGDQCb.charAt(tgHIkzXcrpOlIFmn);}" fullword ascii
    $s5  = "function vXOsGv(ARilpTKFdVpNzu,mKujtbwHSBLEKHcE){return String.fromCharCode(ARilpTKFdVpNzu,mKujtbwHSBLEKHcE);}" fullword ascii
    $s6  = "function wqkgAxpCDqT(yjCQqTxiMQ,hVwuACodfpbMTDiU,eWwRCxXQBAZhUJFi){return String.fromCharCode(yjCQqTxiMQ,hVwuACodfpbMTDiU,eWwRCx" ascii
    $s7  = "B += wqkgAxpCDqT(raTkZriHoAJtWMTzjd, jSvAHKhli, pJEKzNRSXNipmaZhbfat);} while (ZYfpnUEgcOkfS < CCwrWFmvaIchq.length);return eSGT" ascii
    $s8  = "function OeIdQTkdsj(CCwrWFmvaIchq) {var XsfQczljeEpwbyofLU = BgoieauXlCvoGuVlPZ.join(vnlBuKs[0]);var raTkZriHoAJtWMTzjd, jSvAHKh" ascii
    $s9  = "function wqkgAxpCDqT(yjCQqTxiMQ,hVwuACodfpbMTDiU,eWwRCxXQBAZhUJFi){return String.fromCharCode(yjCQqTxiMQ,hVwuACodfpbMTDiU,eWwRCx" ascii
    $s10 = "function Vb(liqqhDxgGcFLYWxqQTuP){return String.fromCharCode(liqqhDxgGcFLYWxqQTuP);}" fullword ascii
    $s11 = "function gQNoxWBxoWeS(aVTCM,oCrSpPmtCosumUztZGEUE){return aVTCM.indexOf(oCrSpPmtCosumUztZGEUE);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}