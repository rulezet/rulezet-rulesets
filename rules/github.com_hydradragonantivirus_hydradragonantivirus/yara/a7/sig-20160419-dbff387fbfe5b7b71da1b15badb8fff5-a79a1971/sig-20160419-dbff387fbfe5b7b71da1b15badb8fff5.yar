rule sig_20160419_dbff387fbfe5b7b71da1b15badb8fff5 {
  meta:
    description = "datamaliciousorder - file 20160419_dbff387fbfe5b7b71da1b15badb8fff5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7abaa8ba5cac1f42292dce8be670e51bc402164b7a07a6dd369dc1457a145f1a"

  strings:
    $s1  = "var Zz = true  , QkBG = elV[7] + elV[9] + elV[11];" fullword ascii
    $s2  = "return NkmZPWs[0] + NkmZPWs[2] + NkmZPWs[4] + \".F\" + NkmZPWs[7] + NkmZPWs[9] + NkmZPWs[12] + NkmZPWs[14];" fullword ascii
    $s3  = "var elV = (\"2.XMLHTTP BXtdpMA NsOoW XML ream St OwuGAZpl AD RJgioZe O BYQT D\").split(\" \");" fullword ascii
    $s4  = "IPIg.open(ddSma,fSUQA,false);" fullword ascii
    $s5  = "return iNkdE.status;" fullword ascii
    $s6  = "return RclglW[XzBO[181-181]]=655-655;" fullword ascii
    $s7  = "return kqdmOOd;" fullword ascii
    $s8  = "function larp(YSuOA) {" fullword ascii
    $s9  = "function GcQJ(plOHo) {" fullword ascii
    $s10 = "function nATav(RclglW) {" fullword ascii
    $s11 = "function FWFynsv(zcLU) {" fullword ascii
    $s12 = "return zcLU[gkzPPkF[0]+gkzPPkF[1]];" fullword ascii
    $s13 = "function CjNCopLhN(nwpUL) {" fullword ascii
    $s14 = "return qnRLmUA[0];" fullword ascii
    $s15 = "function afXfFBl(rrOV,wOtto) {" fullword ascii
    $s16 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s17 = "if (YSuOA != 934-734){return false;} else {return true;}" fullword ascii
    $s18 = "function uyHfR(pod,KPklc) {" fullword ascii
    $s19 = "function rNTfwR(EAiw,dWkMhi) {" fullword ascii
    $s20 = "function bgAf(iNkdE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}