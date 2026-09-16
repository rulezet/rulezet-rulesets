rule sig_20151209_d2d6e6d8a31f98d72f042d61eb2ac6f4 {
  meta:
    description = "datamaliciousorder - file 20151209_d2d6e6d8a31f98d72f042d61eb2ac6f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d45e76264507017280ab863b4949726a1aad411da8c204c04935af56955bb1f3"

  strings:
    $s1  = "function ECLywhe(QTXmUEaBAaWwwFVLJMBSQoOgjDDVJmXeVzOY) {return !isNaN(parseFloat(QTXmUEaBAaWwwFVLJMBSQoOgjDDVJmXeVzOY)) && isFin" ascii
    $s2  = "function ECLywhe(QTXmUEaBAaWwwFVLJMBSQoOgjDDVJmXeVzOY) {return !isNaN(parseFloat(QTXmUEaBAaWwwFVLJMBSQoOgjDDVJmXeVzOY)) && isFin" ascii
    $s3  = "function BaIFgICCWQIIvfWjDEpXCtatIqWXGmvpcdOcBlXckVfdQvkCVCscGv(RkaltNMoEEALD,eCqjRoQpuIruyE){ return ixKbl[yJfdJ(RkaltNMoEEALD[" ascii
    $s4  = "function uiCyAqSCcef(VWuGoUZG,gPGFcd){return VWuGoUZG.split(gPGFcd)}" fullword ascii
    $s5  = "function yJfdJ(WCqcdtyxgko,oNaFgJmbfImIU,NxumUDFt){GvPr=parseInt(WCqcdtyxgko,oNaFgJmbfImIU);TZvcq=GvPr.toString(NxumUDFt);return" ascii
    $s6  = "function BaIFgICCWQIIvfWjDEpXCtatIqWXGmvpcdOcBlXckVfdQvkCVCscGv(RkaltNMoEEALD,eCqjRoQpuIruyE){ return ixKbl[yJfdJ(RkaltNMoEEALD[" ascii
    $s7  = " TZvcq;}function cvwRioLvaHMrsmL(owMeKaypvEvkoVVPR){eval(owMeKaypvEvkoVVPR)}" fullword ascii
    $s8  = "IbhVnAC[ikNGMryzXKy]=(-226+226)/684; while(true) { if(viIbhVnAC[ikNGMryzXKy] > HrjjH[ikNGMryzXKy].length-(57+918)/975) { break; " ascii
    $s9  = "function bPhPdVpLbpBRQpWIq(HrjjH){gShIDOUHtRL= '';for(ikNGMryzXKy=(-68+68)/777; ikNGMryzXKy < (-315+717)/201; ikNGMryzXKy++) {vi" ascii
    $s10 = "return gShIDOUHtRL}" fullword ascii
    $s11 = "function yJfdJ(WCqcdtyxgko,oNaFgJmbfImIU,NxumUDFt){GvPr=parseInt(WCqcdtyxgko,oNaFgJmbfImIU);TZvcq=GvPr.toString(NxumUDFt);return" ascii
    $s12 = "function bPhPdVpLbpBRQpWIq(HrjjH){gShIDOUHtRL= '';for(ikNGMryzXKy=(-68+68)/777; ikNGMryzXKy < (-315+717)/201; ikNGMryzXKy++) {vi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}