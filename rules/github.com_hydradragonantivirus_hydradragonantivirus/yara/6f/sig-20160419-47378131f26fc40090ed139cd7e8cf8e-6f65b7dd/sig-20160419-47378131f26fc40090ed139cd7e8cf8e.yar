rule sig_20160419_47378131f26fc40090ed139cd7e8cf8e {
  meta:
    description = "datamaliciousorder - file 20160419_47378131f26fc40090ed139cd7e8cf8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ded7089fbbf669a50e467daf747614b91c3d2cd8754cd798eb1099954a105f33"

  strings:
    $s1  = "var aJ = true  , OiZd = cSr[7] + cSr[9] + cSr[11];" fullword ascii
    $s2  = "return lRTVGOz[0] + lRTVGOz[2] + lRTVGOz[4] + \".F\" + lRTVGOz[7] + lRTVGOz[9] + lRTVGOz[12] + lRTVGOz[14];" fullword ascii
    $s3  = "qCjf.open(QAQEe,EHuBX,false);" fullword ascii
    $s4  = "var cSr = (\"2.XMLHTTP QfMrykK COHww XML ream St vIlxmugL AD GZbUuiX O krGb D\").split(\" \");" fullword ascii
    $s5  = "function pPctBmw(bwOk,yIHfd) {" fullword ascii
    $s6  = "return cmvkLI[sofB[375-375]]=370-370;" fullword ascii
    $s7  = "function ubVA(LigDg) {" fullword ascii
    $s8  = "function qnMq(sofTR,EHuBX,QAQEe) {" fullword ascii
    $s9  = "function gsQBU(ppqvmhGp,zbpH) {" fullword ascii
    $s10 = "function GizC(ypaCv) {" fullword ascii
    $s11 = "function kAeowEgu(MyXR) {" fullword ascii
    $s12 = "return GBndi;" fullword ascii
    $s13 = "function wPmuK(mwvjAU) {" fullword ascii
    $s14 = "function lPrvdT(tRfnpWE) {" fullword ascii
    $s15 = "return dhQiCed[0];" fullword ascii
    $s16 = "return lKv[SDus[0]](WxddQ);" fullword ascii
    $s17 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s18 = "if(I>=U.length) {break;}" fullword ascii
    $s19 = "function ksqK(FEkpR) {" fullword ascii
    $s20 = "return pPctBmw(yM,pRSANa+PLZkt[220-212]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}