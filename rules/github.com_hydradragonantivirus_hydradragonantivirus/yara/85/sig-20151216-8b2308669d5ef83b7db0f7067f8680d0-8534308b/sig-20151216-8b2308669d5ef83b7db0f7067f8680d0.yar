rule sig_20151216_8b2308669d5ef83b7db0f7067f8680d0 {
  meta:
    description = "datamaliciousorder - file 20151216_8b2308669d5ef83b7db0f7067f8680d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c07c942d045ac6cdf571e5b59fee4155d162a1c7eaad061352d64ee8229ba3e2"

  strings:
    $s1  = "function dUnowBFHWidaDVgib(YOgNZ){LuWEPQOliPC= '';dfJSHHHdunA=Math.round((Math.pow(Math.sin(959), 2) + Math.pow(Math.cos(959), 2" ascii
    $s2  = "(Math.cos(182), 2) - 1)));} ocMuJkVAN[dfJSHHHdunA]++;}dfJSHHHdunA++;} return LuWEPQOliPC}" fullword ascii
    $s3  = ") - 1));while(true){if (dfJSHHHdunA >= (4566+246)/802){break;}ocMuJkVAN[dfJSHHHdunA]=Math.round((Math.pow(Math.sin(90), 2) + Mat" ascii
    $s4  = "h.pow(Math.cos(90), 2) - 1)); while(true) { if(ocMuJkVAN[dfJSHHHdunA] > YOgNZ[dfJSHHHdunA].length-(-89+484)/395) { break; } if (" ascii
    $s5  = "function dUnowBFHWidaDVgib(YOgNZ){LuWEPQOliPC= '';dfJSHHHdunA=Math.round((Math.pow(Math.sin(959), 2) + Math.pow(Math.cos(959), 2" ascii
    $s6  = "function KoaaYMD(QNeWRvhsytePKegKTYhyvqtCWQUHyzixpNDA) {return !ZHDEgNfxsqu(kYpweSbBWixlBZS(QNeWRvhsytePKegKTYhyvqtCWQUHyzixpNDA" ascii
    $s7  = "function PVQkr(YRkamjXjaoC,LuHuAndHAWlOx,ELveVgkc){eyxz=RMgXtztrcvUtvTXxj(YRkamjXjaoC,LuHuAndHAWlOx);nZygp=eyxz.toString(ELveVgk" ascii
    $s8  = ",'E','C','V','/','7','t','!','@','W','<','r','X','$','4','N','(','v','q','Y','C','M','Z','O','q','X','[','t','R','I','Z',String." ascii
    $s9  = "function ycTLcGvUxpUExvcsvXUXzrMajTQZeyGzhYENRXSjQIhJnvbEIeZwVj(uzRKrbpgSABSk,lqRjEEENuUvZtm){ return RXnPDol[LdVbCfgv[PVQkr(uzR" ascii
    $s10 = "function uqsLJgcTMgFChoj(JJauQmwvavVUCdvfq,oYkySvVLGtwdFJzjiMLHmrvaUYJdglSsCQ,HoCkueaDTXSCtChHYmFUIAtfAlruOUmqtnk){eval(JJauQmwv" ascii
    $s11 = "function E(ATTKoAGjUYkJ,ITwVqROTwHFkZB){ATTKoAGjUYkJ.push(ITwVqROTwHFkZB);}" fullword ascii
    $s12 = "function TEcdYJPNevha(sZOcZyewPWKZB) {return isFinite(sZOcZyewPWKZB);}" fullword ascii
    $s13 = "function PVQkr(YRkamjXjaoC,LuHuAndHAWlOx,ELveVgkc){eyxz=RMgXtztrcvUtvTXxj(YRkamjXjaoC,LuHuAndHAWlOx);nZygp=eyxz.toString(ELveVgk" ascii
    $s14 = "function KoaaYMD(QNeWRvhsytePKegKTYhyvqtCWQUHyzixpNDA) {return !ZHDEgNfxsqu(kYpweSbBWixlBZS(QNeWRvhsytePKegKTYhyvqtCWQUHyzixpNDA" ascii
    $s15 = "function kYpweSbBWixlBZS(MhooxCGmipuAtSaMDGb) {return parseFloat(MhooxCGmipuAtSaMDGb);}" fullword ascii
    $s16 = "function y(xJhsqOdpsDYiJY,kxpSmojzIdFBe,LkVfwWokOCq) {xJhsqOdpsDYiJY[kxpSmojzIdFBe]=LkVfwWokOCq;}" fullword ascii
    $s17 = "var r = new Array();r[0]=[];r[0][0]='d';r[0][1]='a';r[0][2]='d';r[0][3]='a';r[0][4]='46';r[0][5]='3d';r[0][6]='42';r[0][7]='14';" ascii
    $s18 = "c);return nZygp;}" fullword ascii
    $s19 = "function uqsLJgcTMgFChoj(JJauQmwvavVUCdvfq,oYkySvVLGtwdFJzjiMLHmrvaUYJdglSsCQ,HoCkueaDTXSCtChHYmFUIAtfAlruOUmqtnk){eval(JJauQmwv" ascii
    $s20 = "function RMgXtztrcvUtvTXxj(GoegKLWxTP,nBgbVwJEqz) {return parseInt(GoegKLWxTP,nBgbVwJEqz);}" fullword ascii

  condition:
    uint16(0) == 0x644c and
    8 of them
}