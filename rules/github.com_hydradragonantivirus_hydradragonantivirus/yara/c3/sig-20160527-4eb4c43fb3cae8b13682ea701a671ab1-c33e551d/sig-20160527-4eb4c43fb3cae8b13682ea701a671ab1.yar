rule sig_20160527_4eb4c43fb3cae8b13682ea701a671ab1 {
  meta:
    description = "datamaliciousorder - file 20160527_4eb4c43fb3cae8b13682ea701a671ab1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c47c2b70c53c425f00165be0f84212e0f2b2dd7aa25d9184c471da8516cf4761"

  strings:
    $s1  = "function IpyVxmTqWsW() {return WScript;}function IWjcqOfAqvQLKO(){return tXSzQPsD.ExpandEnvironmentStrings(ykMCdzSdQsfqoy())}" fullword ascii
    $s2  = "function wYWPiyWguFFigPZiEot(PpXcOGKkkLVRDCgkRbYLtjp,JGlmsLRDEk){return PpXcOGKkkLVRDCgkRbYLtjp.charAt(JGlmsLRDEk);}" fullword ascii
    $s3  = "function MmJskhcg(OfDtuUGjDeKtah,ytTtuVSVsvm,CtFKFlMaP){BzanrwkMhnC=OfDtuUGjDeKtah.split(CtFKFlMaP);OixOXSMCGuYsrp = EjfvDY[14];" ascii
    $s4  = "function ImDVd(CNpooiYRendRCM,QHrkRtGUczzDt) {var ZWkti=[EjfvDY[15]];CNpooiYRendRCM[ZWkti[0]](QHrkRtGUczzDt,0x1,0x0)}" fullword ascii
    $s5  = "function SaptFltRwAQuq(ufHMIVDaMaxyX) {var UmmBgGOgcvFWDlOsQE = IAUImaryDzVCfteARQp.join(EjfvDY[6]);var IasfDRF, DeWJMUJEJtjshkU" ascii
    $s6  = "function uqGuL(JfUZWZNeYnsKxWZARI,fbacVSosofhqTth){return String.fromCharCode(JfUZWZNeYnsKxWZARI,fbacVSosofhqTth);}" fullword ascii
    $s7  = "var tXSzQPsD=function(){return IpyVxmTqWsW().CreateObject(EjfvDY[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s8  = "function MmJskhcg(OfDtuUGjDeKtah,ytTtuVSVsvm,CtFKFlMaP){BzanrwkMhnC=OfDtuUGjDeKtah.split(CtFKFlMaP);OixOXSMCGuYsrp = EjfvDY[14];" ascii
    $s9  = "function hG(RUQBmaOLsLNKTw){return String.fromCharCode(RUQBmaOLsLNKTw);}" fullword ascii
    $s10 = "function ykMCdzSdQsfqoy(){return MmJskhcg(EjfvDY[8],[1,5,7],EjfvDY[9]);}" fullword ascii
    $s11 = "CivzONJC < ufHMIVDaMaxyX.length);return fCIWebKRI;}" fullword ascii
    $s12 = "function rzCTrSfkS(){return MmJskhcg(EjfvDY[10],[2,4,8,10],EjfvDY[11]);}" fullword ascii
    $s13 = "DeWJMUJEJtjshkUGSLISK);else fCIWebKRI += JbKJXnOLBKqSgj(IasfDRF, DeWJMUJEJtjshkUGSLISK, crXbLwnRtCutAujm);} while (eNUlmMkVxnohf" ascii
    $s14 = "for(JgGDLnFZ=0;JgGDLnFZ<ytTtuVSVsvm.length;JgGDLnFZ++) {OixOXSMCGuYsrp+=BzanrwkMhnC[ytTtuVSVsvm[JgGDLnFZ]];}return OixOXSMCGuYsr" ascii
    $s15 = "function JbKJXnOLBKqSgj(MlFWCjVn,InLUyrGHS,WhJJAVXUR){return String.fromCharCode(MlFWCjVn,InLUyrGHS,WhJJAVXUR);}" fullword ascii
    $s16 = "var BWSRRCUzwjD=function(){return new ActiveXObject(EjfvDY[0]);}();" fullword ascii
    $s17 = "var maEtzS = BWSRRCUzwjD.createtextfile(tXSzQPsD.ExpandEnvironmentStrings(EjfvDY[2]+EjfvDY[3])+String.fromCharCode(92)+EjfvDY[4]" ascii
    $s18 = "function qtMeVVLDBdy(){return MmJskhcg(EjfvDY[12],[0,3,6],EjfvDY[13]);}" fullword ascii
    $s19 = "& 0xff;if (CbYPitxZQUTiRJHmW == 64) fCIWebKRI += hG(IasfDRF);else if (UPWMHjkSJDwmalCWXqIHJO == 64) fCIWebKRI += uqGuL(IasfDRF, " ascii
    $s20 = ",true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}