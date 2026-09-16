rule sig_20160531_1208d6e8ba67815a49eaaeed85332fa0 {
  meta:
    description = "datamaliciousorder - file 20160531_1208d6e8ba67815a49eaaeed85332fa0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ea3953ee820c23c3492e9d90d5a0f45ab9615723736e26b7660fefe1444c2a3"

  strings:
    $s1  = "var KzOYFSQkeP=function(){return WScript.CreateObject(CfsOVEIXTzBSMhwj[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function jxFpANcrdtDZaMVjMdlVhj(rHkaSEUpZjaZ,yjYPUgGEDo){return rHkaSEUpZjaZ.charAt(yjYPUgGEDo);}" fullword ascii
    $s3  = "nIKSMvyRlfIx.length);return NivJwH;}" fullword ascii
    $s4  = "function McOJoOoMpyLqHbar(FpkIVNsjpubv,doKORz,TJKswmQZIjqAUxKgEgTjfL){return String.fromCharCode(FpkIVNsjpubv,doKORz,TJKswmQZIjq" ascii
    $s5  = "function rXUyoegcnJ(){return rbbVFnMTVRI(CfsOVEIXTzBSMhwj[13],[0,3,6],CfsOVEIXTzBSMhwj[14]);}" fullword ascii
    $s6  = "function McOJoOoMpyLqHbar(FpkIVNsjpubv,doKORz,TJKswmQZIjqAUxKgEgTjfL){return String.fromCharCode(FpkIVNsjpubv,doKORz,TJKswmQZIjq" ascii
    $s7  = "function fUSaJzAVUtuhzDCeXqZ(naeVpHFOFqs,kiPJppXSfvJaNoou){return String.fromCharCode(naeVpHFOFqs,kiPJppXSfvJaNoou);}" fullword ascii
    $s8  = "function kbsioMzOg(){return rbbVFnMTVRI(CfsOVEIXTzBSMhwj[9],[1,5,7],CfsOVEIXTzBSMhwj[10]);}" fullword ascii
    $s9  = "function cvGynhSVQ(enIKSMvyRlfIx) {var TFyrvljinSacCJzIP = RZlwgZJwgxgmClOOjrdKFVG.join(CfsOVEIXTzBSMhwj[7]);var qXEqjvqkNpXwNU," ascii
    $s10 = "(fclSYZFCRo,0x1,0x0)}function ieAxtx(CeZIbrULAA,vKfSKrlsnBizX,dasgUS){var ZvHyZDK=CeZIbrULAA.createtextfile(vKfSKrlsnBizX,true);" ascii
    $s11 = "AoJHso=0;fAoJHso<tsYqcfAXBmh.length;fAoJHso++) {wFccbA+=MDvenn[tsYqcfAXBmh[fAoJHso]];}return wFccbA.substring(3,wFccbA.length);}" ascii
    $s12 = "B == 64) NivJwH += sN(qXEqjvqkNpXwNU);else if (WtcXZMG == 64) NivJwH += fUSaJzAVUtuhzDCeXqZ(qXEqjvqkNpXwNU, ZAqscxytwRnCVgyslUbi" ascii
    $s13 = "function UXqCeWxfn(){return KzOYFSQkeP.ExpandEnvironmentStrings(kbsioMzOg())}" fullword ascii
    $s14 = "function FqXndgmewkj(lPLhR,fclSYZFCRo) {var EcGMlPX=[CfsOVEIXTzBSMhwj[15]];lPLhR[EcGMlPX[0]]" fullword ascii
    $s15 = "function sN(mkDvBAlL){return String.fromCharCode(mkDvBAlL);}" fullword ascii
    $s16 = "function rbbVFnMTVRI(NcKjvqDdfIkuHj,tsYqcfAXBmh,OSVGXNx){MDvenn=NcKjvqDdfIkuHj.split(OSVGXNx);wFccbA = CfsOVEIXTzBSMhwj[0];for(f" ascii
    $s17 = "(fclSYZFCRo,0x1,0x0)}function ieAxtx(CeZIbrULAA,vKfSKrlsnBizX,dasgUS){var ZvHyZDK=CeZIbrULAA.createtextfile(vKfSKrlsnBizX,true);" ascii
    $s18 = "function UMmdnZC(FvJPtLLiAv,tMKPFQSgLDPqJg){return FvJPtLLiAv.indexOf(tMKPFQSgLDPqJg);}" fullword ascii
    $s19 = "var EqRtYrAfVNTjrU=function(){return new ActiveXObject(CfsOVEIXTzBSMhwj[1]);}();" fullword ascii
    $s20 = "function rbbVFnMTVRI(NcKjvqDdfIkuHj,tsYqcfAXBmh,OSVGXNx){MDvenn=NcKjvqDdfIkuHj.split(OSVGXNx);wFccbA = CfsOVEIXTzBSMhwj[0];for(f" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}