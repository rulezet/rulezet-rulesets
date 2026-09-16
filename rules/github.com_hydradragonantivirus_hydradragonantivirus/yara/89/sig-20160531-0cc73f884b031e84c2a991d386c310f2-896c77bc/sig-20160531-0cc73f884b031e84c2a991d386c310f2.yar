rule sig_20160531_0cc73f884b031e84c2a991d386c310f2 {
  meta:
    description = "datamaliciousorder - file 20160531_0cc73f884b031e84c2a991d386c310f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa6cd1e57b93a8560ccc2dd08efbb7b19407cee1f712ffb4b6dd0d7b00ced623"

  strings:
    $s1  = "var ZYtvNmxBB=function(){return WScript.CreateObject(elaDSCR[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function zDEozhMo(oYGEJEozqRnlvohnDGJdj,rFbRQUGxJVyCwinOvEoWP){return oYGEJEozqRnlvohnDGJdj.charAt(rFbRQUGxJVyCwinOvEoWP);}" fullword ascii
    $s3  = "function i(VnArcOMxezPlytxuYXcDM){return String.fromCharCode(VnArcOMxezPlytxuYXcDM);}" fullword ascii
    $s4  = "function MKlzgYdDe(){return eVUgMgZ(elaDSCR[11],[2,4,8,10],elaDSCR[12]);}" fullword ascii
    $s5  = "function myqOKb(){return eVUgMgZ(elaDSCR[13],[0,3,6],elaDSCR[14]);}" fullword ascii
    $s6  = "J);else if (QFkATLtAYfc == 64) JpAynBue += GleFnpXnXgASHWeFIaqsR(OYlCfNXJ, siEiuoEGWSPoPr);else JpAynBue += XTiyubRIxZMrrzvMocgX" ascii
    $s7  = "true);AmfLSNvZ.WriteLine(qSwdHpblxvoiHk);AmfLSNvZ.Close();}" fullword ascii
    $s8  = "(SNOoV,0x1,0x0)}function VXCVpbJz(sFahdYaUkjYcQg,auGqxmmVP,qSwdHpblxvoiHk){var AmfLSNvZ=sFahdYaUkjYcQg.createtextfile(auGqxmmVP," ascii
    $s9  = "function BYUakZKs(){return ZYtvNmxBB.ExpandEnvironmentStrings(nRMSFhGDWY())}" fullword ascii
    $s10 = "function nRMSFhGDWY(){return eVUgMgZ(elaDSCR[9],[1,5,7],elaDSCR[10]);}" fullword ascii
    $s11 = "function GleFnpXnXgASHWeFIaqsR(PHkumYcbheJEzZWIrUc,fxVvXczifsiliqNKBa){return String.fromCharCode(PHkumYcbheJEzZWIrUc,fxVvXczifs" ascii
    $s12 = "var VQOJdDUE=function(){return new ActiveXObject(elaDSCR[1]);}();" fullword ascii
    $s13 = "function eVUgMgZ(epajKdEakQ,TAvSuWT,UmDaAcNnXBz){qFTDbwpppWJRZE=epajKdEakQ.split(UmDaAcNnXBz);fxRBUAxBS = elaDSCR[0];for(vDjegzw" ascii
    $s14 = "xNp=0;vDjegzwxNp<TAvSuWT.length;vDjegzwxNp++) {fxRBUAxBS+=qFTDbwpppWJRZE[TAvSuWT[vDjegzwxNp]];}return fxRBUAxBS.substring(3,fxRB" ascii
    $s15 = "(SNOoV,0x1,0x0)}function VXCVpbJz(sFahdYaUkjYcQg,auGqxmmVP,qSwdHpblxvoiHk){var AmfLSNvZ=sFahdYaUkjYcQg.createtextfile(auGqxmmVP," ascii
    $s16 = "function GleFnpXnXgASHWeFIaqsR(PHkumYcbheJEzZWIrUc,fxVvXczifsiliqNKBa){return String.fromCharCode(PHkumYcbheJEzZWIrUc,fxVvXczifs" ascii
    $s17 = "function XTiyubRIxZMrrzvMocgX(kAcUT,TvdAw,shGEmqQJgFpAeH){return String.fromCharCode(kAcUT,TvdAw,shGEmqQJgFpAeH);}" fullword ascii
    $s18 = "function eVUgMgZ(epajKdEakQ,TAvSuWT,UmDaAcNnXBz){qFTDbwpppWJRZE=epajKdEakQ.split(UmDaAcNnXBz);fxRBUAxBS = elaDSCR[0];for(vDjegzw" ascii
    $s19 = "function cbYpl(tmUqMSAUVjMF,SNOoV) {var cbWVsfDJfKNHXe=[elaDSCR[15]];tmUqMSAUVjMF[cbWVsfDJfKNHXe[0]]" fullword ascii
    $s20 = "(OYlCfNXJ, siEiuoEGWSPoPr, GowYFzBgrGCHGSDQtvfK);} while (TcFnwVUXqrCYk < dkDCAzDWUfitt.length);return JpAynBue;}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}