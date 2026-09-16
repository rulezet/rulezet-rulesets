rule sig_20151217_4df823cf7e4817a2a6a07b2be8916960 {
  meta:
    description = "datamaliciousorder - file 20151217_4df823cf7e4817a2a6a07b2be8916960.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13486dd5aff9169dfc2f53aec4f11e8e73fe5cd652fa6b160dc641d0df28e31f"

  strings:
    $s1  = ") - 1));while(true){if (ELpEYPByqqk >= (3461+73)/589){break;}kXIbeNUEY[ELpEYPByqqk]=Math.round((Math.pow(Math.sin(355), 2) + Mat" ascii
    $s2  = "ow(Math.cos(946), 2) - 1)));} kXIbeNUEY[ELpEYPByqqk]++;}ELpEYPByqqk++;} return mzXauTzvjYo}" fullword ascii
    $s3  = "function NcJMUbpzLjMHKjhkt(mqXKq){mzXauTzvjYo= '';ELpEYPByqqk=Math.round((Math.pow(Math.sin(869), 2) + Math.pow(Math.cos(869), 2" ascii
    $s4  = "h.pow(Math.cos(355), 2) - 1)); while(true) { if(kXIbeNUEY[ELpEYPByqqk] > mqXKq[ELpEYPByqqk].length-(641+146)/787) { break; } if " ascii
    $s5  = "function NcJMUbpzLjMHKjhkt(mqXKq){mzXauTzvjYo= '';ELpEYPByqqk=Math.round((Math.pow(Math.sin(869), 2) + Math.pow(Math.cos(869), 2" ascii
    $s6  = "function IRjzqIi(JgtUzOHdjRLBNpAyWqejxRVXWfEJFEyMJDVE) {return !IOpyyEmOOPG(nwBwdvcdwDbGgdm(JgtUzOHdjRLBNpAyWqejxRVXWfEJFEyMJDVE" ascii
    $s7  = "function IOpyyEmOOPG(IdfQudGOUNXJVI) {return isNaN(IdfQudGOUNXJVI);}" fullword ascii
    $s8  = "function W(ywrojWwZBhHI,CTeRgUBydajhMn){ywrojWwZBhHI.push(CTeRgUBydajhMn);}" fullword ascii
    $s9  = "function OvauHzSXZxPlbzd(OjCBQiombDWoNIvxG,rIcjKotItGDSmLGRXbmzcNtvSQbOtReFnr,mHFQryiWvWYqZvUnCrglcbswiJLxrdbBTWK){eval(OjCBQiom" ascii
    $s10 = "function IRjzqIi(JgtUzOHdjRLBNpAyWqejxRVXWfEJFEyMJDVE) {return !IOpyyEmOOPG(nwBwdvcdwDbGgdm(JgtUzOHdjRLBNpAyWqejxRVXWfEJFEyMJDVE" ascii
    $s11 = "function zklqLGUNYtqS(wAZvMXBeifpNG) {return isFinite(wAZvMXBeifpNG);}" fullword ascii
    $s12 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s13 = "H);return dlECr;}" fullword ascii
    $s14 = "function OduINvSLeyFmAxjlBRioLfMbzjcwYrYjLZvmgADeSoODkSuGUyCFIV(mamnaZhKkqmMR,JDPzmpPGJVvICb){ return OEJSPJn[xZZWMNXR[yGaZT(mam" ascii
    $s15 = "function OduINvSLeyFmAxjlBRioLfMbzjcwYrYjLZvmgADeSoODkSuGUyCFIV(mamnaZhKkqmMR,JDPzmpPGJVvICb){ return OEJSPJn[xZZWMNXR[yGaZT(mam" ascii
    $s16 = "function A(ZmGabMaZKDvThC,jXXfLyyGZJEmu,OUGWtgrPxhP) {ZmGabMaZKDvThC[jXXfLyyGZJEmu]=OUGWtgrPxhP;}" fullword ascii
    $s17 = "function OvauHzSXZxPlbzd(OjCBQiombDWoNIvxG,rIcjKotItGDSmLGRXbmzcNtvSQbOtReFnr,mHFQryiWvWYqZvUnCrglcbswiJLxrdbBTWK){eval(OjCBQiom" ascii
    $s18 = ",'M','@','V','n','h','L','(','W','5','R','U','j','X','k','Y','L','5','R','?','W','Z','.','v','K','b','t','[','t','e','s',String." ascii
    $s19 = "function FFxJISDJZMrRsGXQY(rRvpSDwPsn,IFKNIKxhiu) {return parseInt(rRvpSDwPsn,IFKNIKxhiu);}" fullword ascii
    $s20 = "function yGaZT(nZCBsJKXjej,ZgwUhVNvBRIgY,kbnfWdDH){bYpD=FFxJISDJZMrRsGXQY(nZCBsJKXjej,ZgwUhVNvBRIgY);dlECr=bYpD.toString(kbnfWdD" ascii

  condition:
    uint16(0) == 0x5a78 and
    8 of them
}