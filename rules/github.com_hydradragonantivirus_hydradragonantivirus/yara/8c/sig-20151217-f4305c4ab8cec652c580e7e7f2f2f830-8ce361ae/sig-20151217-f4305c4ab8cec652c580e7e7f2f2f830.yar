rule sig_20151217_f4305c4ab8cec652c580e7e7f2f2f830 {
  meta:
    description = "datamaliciousorder - file 20151217_f4305c4ab8cec652c580e7e7f2f2f830.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4401a49457c89c3fdc46995ebe09e1106c9358aee7acab3f592e60a56d57f97"

  strings:
    $s1  = ") - 1));while(true){if (zLGaDhyfznH >= (899+139)/173){break;}XITGtWAin[zLGaDhyfznH]=Math.round((Math.pow(Math.sin(824), 2) + Mat" ascii
    $s2  = "function RNCQIAbjnySzwojsh(eXEDm){wGxSutOTDYU= '';zLGaDhyfznH=Math.round((Math.pow(Math.sin(890), 2) + Math.pow(Math.cos(890), 2" ascii
    $s3  = "h.pow(Math.cos(824), 2) - 1)); while(true) { if(XITGtWAin[zLGaDhyfznH] > eXEDm[zLGaDhyfznH].length-(-444+745)/301) { break; } if" ascii
    $s4  = "pow(Math.cos(251), 2) - 1)));} XITGtWAin[zLGaDhyfznH]++;}zLGaDhyfznH++;} return wGxSutOTDYU}" fullword ascii
    $s5  = "zODsDNqtMYJZhndkbRHRHJwvKNDeJAhnhvt([eXEDm[zLGaDhyfznH][XITGtWAin[zLGaDhyfznH]]], Math.round((Math.pow(Math.sin(251), 2) + Math." ascii
    $s6  = "function RNCQIAbjnySzwojsh(eXEDm){wGxSutOTDYU= '';zLGaDhyfznH=Math.round((Math.pow(Math.sin(890), 2) + Math.pow(Math.cos(890), 2" ascii
    $s7  = "function T(XKyymvqIQkeB,ZUmnUWreBftpMk){XKyymvqIQkeB.push(ZUmnUWreBftpMk);}" fullword ascii
    $s8  = "function rObRbKc(sFIkWUaIyoqYJXSRMZqvoILiyXDHMqZnWpxj) {return !GVnMLFxXtzv(leXUssZsUyrAtEZ(sFIkWUaIyoqYJXSRMZqvoILiyXDHMqZnWpxj" ascii
    $s9  = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s10 = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s11 = "function aBswKwIQdyNL(AMkSvtanRVoTK) {return isFinite(AMkSvtanRVoTK);}" fullword ascii
    $s12 = "function leXUssZsUyrAtEZ(IfdQifnhaKUcfxTNERp) {return parseFloat(IfdQifnhaKUcfxTNERp);}" fullword ascii
    $s13 = "function ZJradsuDJsZubfR(fngdYejEIksszJxuP,vkvyzPApqdImYOJKGMjqiRtrdJwSOgsjvR,frBgdeZPHfdigjlVQIOCwfKPUdsSEwVmdtZ){eval(fngdYejE" ascii
    $s14 = "function h(rLhkLernUDPEGr,HBsMjsOkETobV,rXlIUGlIsNk) {rLhkLernUDPEGr[HBsMjsOkETobV]=rXlIUGlIsNk;}" fullword ascii
    $s15 = "function rObRbKc(sFIkWUaIyoqYJXSRMZqvoILiyXDHMqZnWpxj) {return !GVnMLFxXtzv(leXUssZsUyrAtEZ(sFIkWUaIyoqYJXSRMZqvoILiyXDHMqZnWpxj" ascii
    $s16 = "function yuAwF(naBPXdmhHPt,DBzsxUQSpcduk,woICuzzJ){clBG=qAwzrUcrarHlywKBd(naBPXdmhHPt,DBzsxUQSpcduk);OWShQ=clBG.toString(woICuzz" ascii
    $s17 = "J);return OWShQ;}" fullword ascii
    $s18 = "function yuAwF(naBPXdmhHPt,DBzsxUQSpcduk,woICuzzJ){clBG=qAwzrUcrarHlywKBd(naBPXdmhHPt,DBzsxUQSpcduk);OWShQ=clBG.toString(woICuzz" ascii
    $s19 = "function GVnMLFxXtzv(BSRZuamKFpRenB) {return isNaN(BSRZuamKFpRenB);}" fullword ascii
    $s20 = "function mmEDfwlHWsmhqRaBDJpzODsDNqtMYJZhndkbRHRHJwvKNDeJAhnhvt(KchPAjLmcTmGS,kXFHTyltwqytxj){ return lgAkznv[jUXUybZO[yuAwF(Kch" ascii

  condition:
    uint16(0) == 0x556a and
    8 of them
}