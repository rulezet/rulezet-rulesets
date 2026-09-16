rule sig_20151215_cb09eceb874fcf00dc991f10628042de {
  meta:
    description = "datamaliciousorder - file 20151215_cb09eceb874fcf00dc991f10628042de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b9d2d5a2c79a764f0fb71f2ddfb07ca5d65fd0caa3cb5146ea6ae601668bcc3"

  strings:
    $s1  = "ath.pow(Math.cos(266), 2) - 1)); while(true) { if(MbVAVmdyd[ldaqQKENiKh] > yQdhO[ldaqQKENiKh].length-(-860+873)/13) { break; } i" ascii
    $s2  = "function upydeKzGQwUuvxrtW(yQdhO){APxqvdvWkDB= A[1753];for(ldaqQKENiKh=Math.round((Math.pow(Math.sin(399), 2) + Math.pow(Math.co" ascii
    $s3  = ".pow(Math.cos(864), 2) - 1)));} MbVAVmdyd[ldaqQKENiKh]++;}} return APxqvdvWkDB}" fullword ascii
    $s4  = "ImTiIFYjgpjUUbqwBkSXTVjmfsFBzpjHbhFK([yQdhO[ldaqQKENiKh][MbVAVmdyd[ldaqQKENiKh]]], Math.round((Math.pow(Math.sin(864), 2) + Math" ascii
    $s5  = "function upydeKzGQwUuvxrtW(yQdhO){APxqvdvWkDB= A[1753];for(ldaqQKENiKh=Math.round((Math.pow(Math.sin(399), 2) + Math.pow(Math.co" ascii
    $s6  = "function R(pvkJMiDZGpDC,oGLLGiiGdxVmYL){pvkJMiDZGpDC.push(oGLLGiiGdxVmYL);}function s1(sPgHgdASpHGOWImX){if(IphCiFM(sPgHgdASpHGO" ascii
    $s7  = "WImX)) {return (String.fromCharCode(sPgHgdASpHGOWImX) + String.fromCharCode((6445+419)/132));}}" fullword ascii
    $s8  = "function IphCiFM(ORCyGMDOIUccQceGiqiNYGVFxmAGtdGYXDoz) {return !isNaN(parseFloat(ORCyGMDOIUccQceGiqiNYGVFxmAGtdGYXDoz)) && isFin" ascii
    $s9  = "function IphCiFM(ORCyGMDOIUccQceGiqiNYGVFxmAGtdGYXDoz) {return !isNaN(parseFloat(ORCyGMDOIUccQceGiqiNYGVFxmAGtdGYXDoz)) && isFin" ascii
    $s10 = "var A=new Array();" fullword ascii
    $s11 = "function HkdjbAAdyTcRYNvPCMImTiIFYjgpjUUbqwBkSXTVjmfsFBzpjHbhFK(DiAgaPVJnefxf,gzySPDfgcYkSYR){ return zIxGefG[MabnYjHw[TkVgZ(DiA" ascii
    $s12 = "function TkVgZ(DtEYMUUUPOX,CUDwUfisXJitc,cwZYUAmM){AseC=parseInt(DtEYMUUUPOX,CUDwUfisXJitc);jzbcg=AseC.toString(cwZYUAmM);return" ascii
    $s13 = "function OpldDbelwnZ(vzkvSkdN,wzWJhL){return vzkvSkdN.split(wzWJhL)}" fullword ascii
    $s14 = "function R(pvkJMiDZGpDC,oGLLGiiGdxVmYL){pvkJMiDZGpDC.push(oGLLGiiGdxVmYL);}function s1(sPgHgdASpHGOWImX){if(IphCiFM(sPgHgdASpHGO" ascii
    $s15 = "function HkdjbAAdyTcRYNvPCMImTiIFYjgpjUUbqwBkSXTVjmfsFBzpjHbhFK(DiAgaPVJnefxf,gzySPDfgcYkSYR){ return zIxGefG[MabnYjHw[TkVgZ(DiA" ascii
    $s16 = " jzbcg;}function NPYoxnMIhvilneU(CALMJLlIjXbMYglFf,RIKnhVvaqekosnSmJoejmRurIvehKjwzuT,xntKVYOwEekEFPRipwLDLRBoQLpWnOWlHih){eval(" ascii
    $s17 = "function NPYoxnMIhvilneU(CALMJLlIjXbMYglFf){eval(CALMJLlIjXbMYglFf)}" fullword ascii
    $s18 = "function TkVgZ(DtEYMUUUPOX,CUDwUfisXJitc,cwZYUAmM){AseC=parseInt(DtEYMUUUPOX,CUDwUfisXJitc);jzbcg=AseC.toString(cwZYUAmM);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}