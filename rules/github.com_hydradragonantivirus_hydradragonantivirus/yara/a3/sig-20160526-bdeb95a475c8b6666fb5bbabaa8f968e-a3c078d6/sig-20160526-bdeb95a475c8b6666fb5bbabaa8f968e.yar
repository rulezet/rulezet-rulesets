rule sig_20160526_bdeb95a475c8b6666fb5bbabaa8f968e {
  meta:
    description = "datamaliciousorder - file 20160526_bdeb95a475c8b6666fb5bbabaa8f968e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "990f3b432f5879e5f249a4455ff53d89715ad76d8a51515370a47d3c19669230"

  strings:
    $s1  = "Math.pow(Math.sin(563), 2) + Math.pow(Math.cos(563), 2) - 1))-147)) HvBBRhjG += NX(sIFwVvyJRmxRkGh);else if (umVwEDIlVStvkwdKuoq" ascii
    $s2  = "function rkvGOZMnXovKmK(cEQcEaSNNZusP) {var gbAcl = hYPRE.join(IKtwDO[0]);var sIFwVvyJRmxRkGh, rtrXtLaKXbTCib, ubLPVYtHCPn, xoRo" ascii
    $s3  = "round((Math.pow(Math.sin(982), 2) + Math.pow(Math.cos(982), 2) - 1))-45) | QpqeVmxsyantIj<< (163 + Math.round((Math.pow(Math.sin" ascii
    $s4  = "function DpbBPwxhOijyxfi(dbJVZ,KRcwgfSnj){return dbJVZ.charAt(KRcwgfSnj);}" fullword ascii
    $s5  = "oq = TmuOxgmakPRUF(gbAcl,DpbBPwxhOijyxfi(cEQcEaSNNZusP,BnnwDgGafrL++));eIZzDuPfxMLRfQLXwwmBZ = xoRoeSHJNMrwOLyghwA<< (63 + Math." ascii
    $s6  = "function rkvGOZMnXovKmK(cEQcEaSNNZusP) {var gbAcl = hYPRE.join(IKtwDO[0]);var sIFwVvyJRmxRkGh, rtrXtLaKXbTCib, ubLPVYtHCPn, xoRo" ascii
    $s7  = "function XWgLCKPysYXCYAxAPVQDclj(FzEvqUFuabjlMznMPhOW,czlVcpCgzgGilvtiQydqb,OqJOpxEWcxqAKbOBLss){return String.fromCharCode(FzEv" ascii
    $s8  = "sIFwVvyJRmxRkGh, rtrXtLaKXbTCib);else HvBBRhjG += XWgLCKPysYXCYAxAPVQDclj(sIFwVvyJRmxRkGh, rtrXtLaKXbTCib, ubLPVYtHCPn);} while " ascii
    $s9  = "function XWgLCKPysYXCYAxAPVQDclj(FzEvqUFuabjlMznMPhOW,czlVcpCgzgGilvtiQydqb,OqJOpxEWcxqAKbOBLss){return String.fromCharCode(FzEv" ascii
    $s10 = "function TmuOxgmakPRUF(UlxQIxmHmpOFYMwPw,ALBxQAYbkpiB){return UlxQIxmHmpOFYMwPw.indexOf(ALBxQAYbkpiB);}" fullword ascii
    $s11 = "function NX(AsbDymwFKBoXmcgW){return String.fromCharCode(AsbDymwFKBoXmcgW);}" fullword ascii
    $s12 = "(BnnwDgGafrL < cEQcEaSNNZusP.length);return HvBBRhjG;}" fullword ascii
    $s13 = "function IiQAnVsIWyYLNrpcuSQKHKly(ByGZAKwiiPHkpJzzTsdWbi,rDcrlxXyDHMRJSt){return String.fromCharCode(ByGZAKwiiPHkpJzzTsdWbi,rDcr" ascii
    $s14 = "function IiQAnVsIWyYLNrpcuSQKHKly(ByGZAKwiiPHkpJzzTsdWbi,rDcrlxXyDHMRJSt){return String.fromCharCode(ByGZAKwiiPHkpJzzTsdWbi,rDcr" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}