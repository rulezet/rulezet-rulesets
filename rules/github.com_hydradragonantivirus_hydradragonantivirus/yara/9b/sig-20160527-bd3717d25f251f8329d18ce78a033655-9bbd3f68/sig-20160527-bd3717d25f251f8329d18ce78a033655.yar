rule sig_20160527_bd3717d25f251f8329d18ce78a033655 {
  meta:
    description = "datamaliciousorder - file 20160527_bd3717d25f251f8329d18ce78a033655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a9731e75773531ef401904e5c6b5a477f6b512c4fc913f3830afd30bd491ac3"

  strings:
    $s1  = "function xYirDioF() {return WScript;}function PeFmfKjuc(){return YvRvg.ExpandEnvironmentStrings(hrFqSr())}" fullword ascii
    $s2  = "function OOIBLa(iTCraMjRXnMgzlSFfEUiHuM,rWJZwWNIigBdLneaJfdSCul){return iTCraMjRXnMgzlSFfEUiHuM.charAt(rWJZwWNIigBdLneaJfdSCul);" ascii
    $s3  = "function OOIBLa(iTCraMjRXnMgzlSFfEUiHuM,rWJZwWNIigBdLneaJfdSCul){return iTCraMjRXnMgzlSFfEUiHuM.charAt(rWJZwWNIigBdLneaJfdSCul);" ascii
    $s4  = "eYiQ.length);return qJIFytqPG;}" fullword ascii
    $s5  = ")+oVpVyZxEmvl[4],true);" fullword ascii
    $s6  = "function kAZjXjTPjgVEomUjcqS(qRhKoGInFxJpzqBZetCJn,KzwtEXaZGhgAEETVmFmoE,lHsHiEaeKEchsGfjyWzYFt){return String.fromCharCode(qRhK" ascii
    $s7  = "function lXzHuqamrr(){return URswXRyjOKuGz(oVpVyZxEmvl[12],[0,3,6],oVpVyZxEmvl[13]);}" fullword ascii
    $s8  = "function URswXRyjOKuGz(KsURLBftiqcUq,NXKeuoNDhY,ELRtenPbAdp){UMuYa=KsURLBftiqcUq.split(ELRtenPbAdp);civAiYhpAHw = oVpVyZxEmvl[14" ascii
    $s9  = " == 64) qJIFytqPG += qz(MwULynbWwcXFsBcYsos);else if (kJEdxZADuznSxdTrmZH == 64) qJIFytqPG += yahCxHQrKjedGvh(MwULynbWwcXFsBcYso" ascii
    $s10 = "var YvRvg=function(){return xYirDioF().CreateObject(oVpVyZxEmvl[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s11 = "function yahCxHQrKjedGvh(iecxJAbkStIN,wUHqzZOzoqJlhFoOrnakRlla){return String.fromCharCode(iecxJAbkStIN,wUHqzZOzoqJlhFoOrnakRlla" ascii
    $s12 = "function hrFqSr(){return URswXRyjOKuGz(oVpVyZxEmvl[8],[1,5,7],oVpVyZxEmvl[9]);}" fullword ascii
    $s13 = "var AdzAVMELOyrRU = jXlEnuGL.createtextfile(YvRvg.ExpandEnvironmentStrings(oVpVyZxEmvl[2]+oVpVyZxEmvl[3])+String.fromCharCode(92" ascii
    $s14 = "function URswXRyjOKuGz(KsURLBftiqcUq,NXKeuoNDhY,ELRtenPbAdp){UMuYa=KsURLBftiqcUq.split(ELRtenPbAdp);civAiYhpAHw = oVpVyZxEmvl[14" ascii
    $s15 = "function VFIYZ(XXxsfETMzeYiQ) {var gHqcYJUcNPPrBr = cWJAleitWIIYxTadUjwcIwM.join(oVpVyZxEmvl[6]);var MwULynbWwcXFsBcYsos, bALUyZ" ascii
    $s16 = "function qz(iWDIGtqjiKGCx){return String.fromCharCode(iWDIGtqjiKGCx);}" fullword ascii
    $s17 = "function PBIMbUATKI(){return URswXRyjOKuGz(oVpVyZxEmvl[10],[2,4,8,10],oVpVyZxEmvl[11]);}" fullword ascii
    $s18 = "var jXlEnuGL=function(){return new ActiveXObject(oVpVyZxEmvl[0]);}();" fullword ascii
    $s19 = "function VFIYZ(XXxsfETMzeYiQ) {var gHqcYJUcNPPrBr = cWJAleitWIIYxTadUjwcIwM.join(oVpVyZxEmvl[6]);var MwULynbWwcXFsBcYsos, bALUyZ" ascii
    $s20 = "function kAZjXjTPjgVEomUjcqS(qRhKoGInFxJpzqBZetCJn,KzwtEXaZGhgAEETVmFmoE,lHsHiEaeKEchsGfjyWzYFt){return String.fromCharCode(qRhK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}