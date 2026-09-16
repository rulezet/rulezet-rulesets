rule sig_20160323_750a3fe01759a0b7c776895923c11b98 {
  meta:
    description = "datamaliciousorder - file 20160323_750a3fe01759a0b7c776895923c11b98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee068b68272bb0e88c041458a65a047da3d22a4c9d3715d215f30d154711bfa1"

  strings:
    $s1  = "return WScript.CreateObject(OcsCR);" fullword ascii
    $s2  = "var mR = true  , XxYg = nal[7] + nal[9] + nal[11];" fullword ascii
    $s3  = "return FACNaOV[0] + FACNaOV[2] + FACNaOV[4] + \".F\" + FACNaOV[7] + FACNaOV[9] + FACNaOV[12] + FACNaOV[14];" fullword ascii
    $s4  = "var nal = (\"2.XMLHTTP ZkLXDAS kXUcu XML ream St hyqvzQxA AD FuIOGVf O CQAR D\").split(\" \");" fullword ascii
    $s5  = "vaxO.open(jkdan,CRAww,false);" fullword ascii
    $s6  = "var FACNaOV = qTehl(uRLDZaWZlb+\" \"+\"System lu NvhIl Obj cblqAt ect dVgYhHZ RJHbc\", \" \");" fullword ascii
    $s7  = "function bejFCyDF(hrES) {" fullword ascii
    $s8  = "function kjJk(NLCWd) {" fullword ascii
    $s9  = "function MaZecdT(JwAw) {" fullword ascii
    $s10 = "rhg = x; break; " fullword ascii
    $s11 = "function hAxOZxkB(pPm) {" fullword ascii
    $s12 = "function oIlE(bzbvU,kpsBs) {" fullword ascii
    $s13 = "return PPYnJsB(UE,RyIFC[905-899]+RyIFC[170-163]+RyIFC[420-412]);" fullword ascii
    $s14 = "return JwAw[uhPhGS[0]];" fullword ascii
    $s15 = "if (o >= POOuU.length) {break;}" fullword ascii
    $s16 = "return pPm.size;" fullword ascii
    $s17 = "function AVQIu(YJKjsg) {" fullword ascii
    $s18 = "function OVti(FvlOs) {" fullword ascii
    $s19 = "function IPoG(owBxK,rLSrG) {" fullword ascii
    $s20 = "function PPYnJsB(IUNH,MtLwT) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}