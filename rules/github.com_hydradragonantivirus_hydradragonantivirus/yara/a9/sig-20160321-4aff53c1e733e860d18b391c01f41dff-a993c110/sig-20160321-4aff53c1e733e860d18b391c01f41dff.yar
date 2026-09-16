rule sig_20160321_4aff53c1e733e860d18b391c01f41dff {
  meta:
    description = "datamaliciousorder - file 20160321_4aff53c1e733e860d18b391c01f41dff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c74643ff5cc1d7a41d5c8f67791468aaacf56eb61752441c6e1db345427f38a"

  strings:
    $s1  = "return WScript.CreateObject(wzHtH);" fullword ascii
    $s2  = "function sHjY(gEtpJ) {" fullword ascii
    $s3  = "if (gEtpJ == 549-349){return true;} else {return false;}" fullword ascii
    $s4  = "var qg = true  , HnFq = ZIO[7] + ZIO[9] + ZIO[11];" fullword ascii
    $s5  = "return GDWLRWk[0] + GDWLRWk[2] + GDWLRWk[4] + \".F\" + GDWLRWk[7] + GDWLRWk[9] + GDWLRWk[12] + GDWLRWk[14];" fullword ascii
    $s6  = "iLwNk.open(tvyYk,HrNVP,false);" fullword ascii
    $s7  = "var GDWLRWk = WFhEj(xMHCbFDPLr+\" \"+\"System bR uayDk Obj OnUexY ect DlhAaee YJckG\", \" \");" fullword ascii
    $s8  = "var ZIO = (\"2.XMLHTTP PWUCnKu urUgh XML ream St knefANjZ AD kPrqFql O IIRF D\").split(\" \");" fullword ascii
    $s9  = "function rAAKAvZWX(AmxbK) {" fullword ascii
    $s10 = "function zLEZC(VVHMFT) {" fullword ascii
    $s11 = "return dzZ.size;" fullword ascii
    $s12 = "OKn = v; break; " fullword ascii
    $s13 = "function taSYywKs(HCEB) {" fullword ascii
    $s14 = "function OkJH(jNSxr) {" fullword ascii
    $s15 = "function aYgFvweni(vJzwiTGxmlh) {" fullword ascii
    $s16 = "function AqCd(yWAKK,CVltz) {" fullword ascii
    $s17 = "function rdRpu(JugQnt) {" fullword ascii
    $s18 = "return QLGQF.status;" fullword ascii
    $s19 = "return IUcH[oNHnxJ[0]];" fullword ascii
    $s20 = "function lJnO(wzHtH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}