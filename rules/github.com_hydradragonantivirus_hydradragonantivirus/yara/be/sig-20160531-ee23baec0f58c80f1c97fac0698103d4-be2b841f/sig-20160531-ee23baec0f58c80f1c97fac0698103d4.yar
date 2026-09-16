rule sig_20160531_ee23baec0f58c80f1c97fac0698103d4 {
  meta:
    description = "datamaliciousorder - file 20160531_ee23baec0f58c80f1c97fac0698103d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f4d1443b1fd219765c85c69b64d903ccd7b1927a09c5dbb5471b0b74024adae"

  strings:
    $s1  = "var zIAyuxuOnko=function(){return WScript.CreateObject(iIsAJHcFVkFUfdZbW[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function gvQyLviMSKFadfWpdwGmGyo(WyNJaQlK,ESvjrV){return WyNJaQlK.charAt(ESvjrV);}" fullword ascii
    $s3  = " & 0xff;pbSYoRvKJgOEvI = ZuUKthLTe & 0xff;if (ddKIEayeTfoOFlhYNcs == 64) HgZbUtFkcQGBTmPBDX += da(ZoGTeulgvcxK);else if (LmaCiNe" ascii
    $s4  = "GOjqLGQUUVqXM == 64) HgZbUtFkcQGBTmPBDX += fmIjDDaIilUkwMwaQalAcSn(ZoGTeulgvcxK, NaUqglCqGlMLM);else HgZbUtFkcQGBTmPBDX += Rhnkw" ascii
    $s5  = "function VRZQHsasR(KRSLwCSO,mHFjiRujDlAs) {var azrPortm=[iIsAJHcFVkFUfdZbW[15]];KRSLwCSO[azrPortm[0]]" fullword ascii
    $s6  = "XILs(ZoGTeulgvcxK, NaUqglCqGlMLM, pbSYoRvKJgOEvI);} while (YVCuMb < ZJuaTUYrzitit.length);return HgZbUtFkcQGBTmPBDX;}" fullword ascii
    $s7  = "function cSdxydKc(){return OKkbwZwPtdiTcD(iIsAJHcFVkFUfdZbW[11],[2,4,8,10],iIsAJHcFVkFUfdZbW[12]);}" fullword ascii
    $s8  = "function da(LGXgJeXg){return String.fromCharCode(LGXgJeXg);}" fullword ascii
    $s9  = "function YQpHM(){return zIAyuxuOnko.ExpandEnvironmentStrings(lHjpoziJnw())}" fullword ascii
    $s10 = "function lHjpoziJnw(){return OKkbwZwPtdiTcD(iIsAJHcFVkFUfdZbW[9],[1,5,7],iIsAJHcFVkFUfdZbW[10]);}" fullword ascii
    $s11 = "function fmIjDDaIilUkwMwaQalAcSn(bHRrDLmiLHPeKh,sNaKIWQqKNLtzmSESmFoq){return String.fromCharCode(bHRrDLmiLHPeKh,sNaKIWQqKNLtzmS" ascii
    $s12 = "function mCwqOxb(){return OKkbwZwPtdiTcD(iIsAJHcFVkFUfdZbW[13],[0,3,6],iIsAJHcFVkFUfdZbW[14]);}" fullword ascii
    $s13 = "(mHFjiRujDlAs,0x1,0x0)}function ceXPnVppOP(AUMUMKFupSe,TedbJnpSIu,ZHDHaHHYbQZNcs){var zFOho=AUMUMKFupSe.createtextfile(TedbJnpSI" ascii
    $s14 = "(RtkLpxEZjHgL=0;RtkLpxEZjHgL<sIfVkgAzV.length;RtkLpxEZjHgL++) {KjARyP+=LhdktIvzprpr[sIfVkgAzV[RtkLpxEZjHgL]];}return KjARyP.subs" ascii
    $s15 = "function RhnkwXILs(KtyHatzVxO,KtLuhudx,VFrNnS){return String.fromCharCode(KtyHatzVxO,KtLuhudx,VFrNnS);}" fullword ascii
    $s16 = "function fmIjDDaIilUkwMwaQalAcSn(bHRrDLmiLHPeKh,sNaKIWQqKNLtzmSESmFoq){return String.fromCharCode(bHRrDLmiLHPeKh,sNaKIWQqKNLtzmS" ascii
    $s17 = "var FJZYa=function(){return new ActiveXObject(iIsAJHcFVkFUfdZbW[1]);}();" fullword ascii
    $s18 = "u,true);zFOho.WriteLine(ZHDHaHHYbQZNcs);zFOho.Close();}" fullword ascii
    $s19 = "(mHFjiRujDlAs,0x1,0x0)}function ceXPnVppOP(AUMUMKFupSe,TedbJnpSIu,ZHDHaHHYbQZNcs){var zFOho=AUMUMKFupSe.createtextfile(TedbJnpSI" ascii
    $s20 = "function QlJwDJlJ(ZJuaTUYrzitit) {var YrrFCaQBgTnaVPKjtuWjfOt = AaEeKtKWMuoOcfTGxsmb.join(iIsAJHcFVkFUfdZbW[7]);var ZoGTeulgvcxK" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}