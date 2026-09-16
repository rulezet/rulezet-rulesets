rule sig_20151215_2791a00b924a29b7c841277b987dea8e {
  meta:
    description = "datamaliciousorder - file 20151215_2791a00b924a29b7c841277b987dea8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8d9af30aed72ff6c0760c5253b90478b8f38544afa90bec3219c27eaca3a858"

  strings:
    $s1  = "ath.pow(Math.cos(341), 2) - 1)); while(true) { if(MNZDOHFvM[BgDHDVlUDLq] > KBYUs[BgDHDVlUDLq].length-(-685+850)/165) { break; } " ascii
    $s2  = "function AIMcYVTiatOfbnBel(KBYUs){HJaHtHHVsRO= e[1822];for(BgDHDVlUDLq=Math.round((Math.pow(Math.sin(801), 2) + Math.pow(Math.co" ascii
    $s3  = "h.pow(Math.cos(886), 2) - 1)));} MNZDOHFvM[BgDHDVlUDLq]++;}} return HJaHtHHVsRO}" fullword ascii
    $s4  = "function AIMcYVTiatOfbnBel(KBYUs){HJaHtHHVsRO= e[1822];for(BgDHDVlUDLq=Math.round((Math.pow(Math.sin(801), 2) + Math.pow(Math.co" ascii
    $s5  = "function Q(gxbbUiIrXEPC,ppoMQbrWWIrEdz){gxbbUiIrXEPC.push(ppoMQbrWWIrEdz);}function x3(bXQpgCnhmbEQHdRN){if(BwJDPyi(bXQpgCnhmbEQ" ascii
    $s6  = "HdRN)) {return (String.fromCharCode(bXQpgCnhmbEQHdRN) + String.fromCharCode((2940+404)/44));}}" fullword ascii
    $s7  = "function BwJDPyi(XKveZWhlskBVAwcSTeXHfhtoMPiMAvUbNwdQ) {return !isNaN(parseFloat(XKveZWhlskBVAwcSTeXHfhtoMPiMAvUbNwdQ)) && isFin" ascii
    $s8  = "function BwJDPyi(XKveZWhlskBVAwcSTeXHfhtoMPiMAvUbNwdQ) {return !isNaN(parseFloat(XKveZWhlskBVAwcSTeXHfhtoMPiMAvUbNwdQ)) && isFin" ascii
    $s9  = "function ApGWnyMnwjUVkZixMAmBMDKfVAUcLVHtkIVDavMaseAtbsjswPvodf(YBamVqkvkQpEC,XiZjJHzYtjAsmK){ return JFwXlVB[WbnlSmlo[JSfOa(YBa" ascii
    $s10 = "function Q(gxbbUiIrXEPC,ppoMQbrWWIrEdz){gxbbUiIrXEPC.push(ppoMQbrWWIrEdz);}function x3(bXQpgCnhmbEQHdRN){if(BwJDPyi(bXQpgCnhmbEQ" ascii
    $s11 = "function iQLEWRPivLn(TJHcNFsI,DhcZeI){return TJHcNFsI.split(DhcZeI)}" fullword ascii
    $s12 = "var e=new Array();" fullword ascii
    $s13 = "function ApGWnyMnwjUVkZixMAmBMDKfVAUcLVHtkIVDavMaseAtbsjswPvodf(YBamVqkvkQpEC,XiZjJHzYtjAsmK){ return JFwXlVB[WbnlSmlo[JSfOa(YBa" ascii
    $s14 = "function jsDVKYCCOEjfXvP(sKoDqCMcTSMLxeNkU){eval(sKoDqCMcTSMLxeNkU)}" fullword ascii
    $s15 = "function JSfOa(prOcMJNSbJR,GdDampYfjqzIs,XvAjSNzI){zZGP=parseInt(prOcMJNSbJR,GdDampYfjqzIs);DOgiy=zZGP.toString(XvAjSNzI);return" ascii
    $s16 = " DOgiy;}function jsDVKYCCOEjfXvP(sKoDqCMcTSMLxeNkU,pCWRSpUwOugFCajrCLqKnwmFsiBRItBQKZ,pHgMNHUutjaWhwbkXShurNzmVFXnAbYgQcJ){eval(" ascii
    $s17 = "function JSfOa(prOcMJNSbJR,GdDampYfjqzIs,XvAjSNzI){zZGP=parseInt(prOcMJNSbJR,GdDampYfjqzIs);DOgiy=zZGP.toString(XvAjSNzI);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}