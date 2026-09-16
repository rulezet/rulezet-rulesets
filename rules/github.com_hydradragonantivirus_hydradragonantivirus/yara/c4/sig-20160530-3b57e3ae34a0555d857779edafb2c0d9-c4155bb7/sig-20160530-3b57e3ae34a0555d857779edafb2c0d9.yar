rule sig_20160530_3b57e3ae34a0555d857779edafb2c0d9 {
  meta:
    description = "datamaliciousorder - file 20160530_3b57e3ae34a0555d857779edafb2c0d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a8628cd00f8f2e0c5d411a2e8c403d8dee5b17941c4aac09711b53a68092a6"

  strings:
    $s1  = "var YAHzevAqD=function(){return WScript.CreateObject(EdSkUpzmtwLsEc[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function PAJwADba(hWLNZKNhzORoNsp,NgIypSVHbqYnjJieaBSzwa){return hWLNZKNhzORoNsp.charAt(NgIypSVHbqYnjJieaBSzwa);}" fullword ascii
    $s3  = "function EkbuXaiXnAeq(){return KgsNpMPSGPkomw(EdSkUpzmtwLsEc[11],[2,4,8,10],EdSkUpzmtwLsEc[12]);}" fullword ascii
    $s4  = "function adcFvypCeRMdq(){return KgsNpMPSGPkomw(EdSkUpzmtwLsEc[9],[1,5,7],EdSkUpzmtwLsEc[10]);}" fullword ascii
    $s5  = "var KDEyH=function(){return new ActiveXObject(EdSkUpzmtwLsEc[1]);}();" fullword ascii
    $s6  = "function WT(ybVcKCrn){return String.fromCharCode(ybVcKCrn);}" fullword ascii
    $s7  = "92)+EdSkUpzmtwLsEc[5],true);" fullword ascii
    $s8  = "function RjtKvUySWyFW(TYlZOO,XnoOZCilVnD) {var QMyKRPN=[EdSkUpzmtwLsEc[15]];TYlZOO[QMyKRPN[0]]" fullword ascii
    $s9  = "VfQZEBYYLudZYHnivQ);else fSLoToNnmFEFBupbM += azgMlUltwjWZMe(YdzkRBUjPzRJ, eVfQZEBYYLudZYHnivQ, UTUttfoGKrZuR);} while (GvOyFliV" ascii
    $s10 = "Oyh < JHjzrBnMUmVDF.length);return fSLoToNnmFEFBupbM;}" fullword ascii
    $s11 = "function KgsNpMPSGPkomw(xfmQEsXsYGs,lOElAeUQThPBO,GLXuBBOCcf){XBPSfqLNmUE=xfmQEsXsYGs.split(GLXuBBOCcf);mOSZccVOfwA = EdSkUpzmtw" ascii
    $s12 = "function tjUWlJr(lKiRPdhD,NMciJHGyNnJRKSrsmpcoee){return String.fromCharCode(lKiRPdhD,NMciJHGyNnJRKSrsmpcoee);}" fullword ascii
    $s13 = "function GFLfcqAXlJK(){return KgsNpMPSGPkomw(EdSkUpzmtwLsEc[13],[0,3,6],EdSkUpzmtwLsEc[14]);}" fullword ascii
    $s14 = "function BgXgkiHodSisxoNlxbmLouXL(fuQeAVGJgvunyyLepbXlTn,GKLGTMV){return fuQeAVGJgvunyyLepbXlTn.indexOf(GKLGTMV);}" fullword ascii
    $s15 = "u]];}return mOSZccVOfwA.substring(3,mOSZccVOfwA.length);}" fullword ascii
    $s16 = "function KgsNpMPSGPkomw(xfmQEsXsYGs,lOElAeUQThPBO,GLXuBBOCcf){XBPSfqLNmUE=xfmQEsXsYGs.split(GLXuBBOCcf);mOSZccVOfwA = EdSkUpzmtw" ascii
    $s17 = "var RXdvaNXL = KDEyH.createtextfile(YAHzevAqD.ExpandEnvironmentStrings(EdSkUpzmtwLsEc[3]+EdSkUpzmtwLsEc[4])+String.fromCharCode(" ascii
    $s18 = "lJebNZmPNqaDJhB == 64) fSLoToNnmFEFBupbM += WT(YdzkRBUjPzRJ);else if (iPQmxu == 64) fSLoToNnmFEFBupbM += tjUWlJr(YdzkRBUjPzRJ, e" ascii
    $s19 = "function KEjfHBSXtDj(JHjzrBnMUmVDF) {var gTVqGKpGKhMjbGH = WnTGrdSb.join(EdSkUpzmtwLsEc[7]);var YdzkRBUjPzRJ, eVfQZEBYYLudZYHniv" ascii
    $s20 = "function KEjfHBSXtDj(JHjzrBnMUmVDF) {var gTVqGKpGKhMjbGH = WnTGrdSb.join(EdSkUpzmtwLsEc[7]);var YdzkRBUjPzRJ, eVfQZEBYYLudZYHniv" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}