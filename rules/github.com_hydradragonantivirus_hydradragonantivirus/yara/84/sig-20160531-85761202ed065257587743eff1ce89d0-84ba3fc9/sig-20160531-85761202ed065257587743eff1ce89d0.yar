rule sig_20160531_85761202ed065257587743eff1ce89d0 {
  meta:
    description = "datamaliciousorder - file 20160531_85761202ed065257587743eff1ce89d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a2bf8c2258368d90a0d63f713eaa4d1fb9ba0bc91bf81caf68f956fe35e6018"

  strings:
    $s1  = "var twsbT=function(){return WScript.CreateObject(lakogMYonUeRe[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function mWYCuHejWSdTezYVoJ(UASeJJCDCxYOyi,JuMmYnT){return UASeJJCDCxYOyi.charAt(JuMmYnT);}" fullword ascii
    $s3  = "Ox=0;ndtSreyPOcdiOx<HtDnVQZ.length;ndtSreyPOcdiOx++) {gntJT+=aWSKsA[HtDnVQZ[ndtSreyPOcdiOx]];}return gntJT.substring(3,gntJT.len" ascii
    $s4  = "function MCnZhVydLxyqm(){return HRNcMKrawXzr(lakogMYonUeRe[9],[1,5,7],lakogMYonUeRe[10]);}" fullword ascii
    $s5  = "xff;if (zjeSOEnAnRAHDVeZWLtpwnf == 64) hWfisJxLQtesUSUXa += LE(DorVbzbCfIyKvvp);else if (Asbls == 64) hWfisJxLQtesUSUXa += XtwaE" ascii
    $s6  = "function Uurqb(rhGKpSoWJZzdvMtzd,WGObhtsznAfldHqWClyNlU){return rhGKpSoWJZzdvMtzd.indexOf(WGObhtsznAfldHqWClyNlU);}" fullword ascii
    $s7  = "function MatQnxbG(){return HRNcMKrawXzr(lakogMYonUeRe[11],[2,4,8,10],lakogMYonUeRe[12]);}" fullword ascii
    $s8  = "(iToSFQgsYmdM,0x1,0x0)}function EFRfEbEjiziZCi(FrQZfKOMTFNzfg,uCkRMZ,sjhDpvdmtGVP){var AktdUY=FrQZfKOMTFNzfg.createtextfile(uCkR" ascii
    $s9  = "function LE(NLlHyPbEMkxeUPaTdW){return String.fromCharCode(NLlHyPbEMkxeUPaTdW);}" fullword ascii
    $s10 = "function XtwaEasCIHdyaoNGSDGUswRO(bwuejSGdIzvGjkghDWWvTIf,puAlzlCQNOBSVWRf){return String.fromCharCode(bwuejSGdIzvGjkghDWWvTIf,p" ascii
    $s11 = "function GJhvdEnARQvyUBXLNuXMxDJ(RctturHVdz,YTyrHouyb,zenOTt){return String.fromCharCode(RctturHVdz,YTyrHouyb,zenOTt);}" fullword ascii
    $s12 = "function hGdfZKddXB(){return twsbT.ExpandEnvironmentStrings(MCnZhVydLxyqm())}" fullword ascii
    $s13 = "MZ,true);AktdUY.WriteLine(sjhDpvdmtGVP);AktdUY.Close();}" fullword ascii
    $s14 = "(iToSFQgsYmdM,0x1,0x0)}function EFRfEbEjiziZCi(FrQZfKOMTFNzfg,uCkRMZ,sjhDpvdmtGVP){var AktdUY=FrQZfKOMTFNzfg.createtextfile(uCkR" ascii
    $s15 = "var snmOR=function(){return new ActiveXObject(lakogMYonUeRe[1]);}();" fullword ascii
    $s16 = "asCIHdyaoNGSDGUswRO(DorVbzbCfIyKvvp, HrKLiYxvpvbVkCnS);else hWfisJxLQtesUSUXa += GJhvdEnARQvyUBXLNuXMxDJ(DorVbzbCfIyKvvp, HrKLiY" ascii
    $s17 = "function CVdLPvfz(HHaoPcxzQFNvh) {var MTmKaElwTjgvU = yucfrkFlHGhVFOsgS.join(lakogMYonUeRe[7]);var DorVbzbCfIyKvvp, HrKLiYxvpvbV" ascii
    $s18 = "function CegkHGGXG(UcbPLqVUbVTvE,iToSFQgsYmdM) {var GlPMwuArY=[lakogMYonUeRe[15]];UcbPLqVUbVTvE[GlPMwuArY[0]]" fullword ascii
    $s19 = "function CVdLPvfz(HHaoPcxzQFNvh) {var MTmKaElwTjgvU = yucfrkFlHGhVFOsgS.join(lakogMYonUeRe[7]);var DorVbzbCfIyKvvp, HrKLiYxvpvbV" ascii
    $s20 = "function XtwaEasCIHdyaoNGSDGUswRO(bwuejSGdIzvGjkghDWWvTIf,puAlzlCQNOBSVWRf){return String.fromCharCode(bwuejSGdIzvGjkghDWWvTIf,p" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}