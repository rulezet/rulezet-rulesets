rule sig_20151217_5e0fa62e5d4e817cfc5cd305a47c28fa {
  meta:
    description = "datamaliciousorder - file 20151217_5e0fa62e5d4e817cfc5cd305a47c28fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97f9dfba3cfcd6731928c72c1cd1d1c16f6ea06b810cbd9e6f616c0e3d704e94"

  strings:
    $s1  = "th.pow(Math.cos(719), 2) - 1)); while(true) { if(RGIkauzrs[fbcRWlOgtKc] > LQkON[fbcRWlOgtKc].length-(-633+749)/116) { break; } i" ascii
    $s2  = "function OkJSrZCtNfUnhOIOy(LQkON){tcwzPQpKGrj= '';fbcRWlOgtKc=Math.round((Math.pow(Math.sin(716), 2) + Math.pow(Math.cos(716), 2" ascii
    $s3  = ") - 1));while(true){if (fbcRWlOgtKc >= (2222+214)/406){break;}RGIkauzrs[fbcRWlOgtKc]=Math.round((Math.pow(Math.sin(719), 2) + Ma" ascii
    $s4  = "ow(Math.cos(727), 2) - 1)));} RGIkauzrs[fbcRWlOgtKc]++;}fbcRWlOgtKc++;} return tcwzPQpKGrj}" fullword ascii
    $s5  = "function OkJSrZCtNfUnhOIOy(LQkON){tcwzPQpKGrj= '';fbcRWlOgtKc=Math.round((Math.pow(Math.sin(716), 2) + Math.pow(Math.cos(716), 2" ascii
    $s6  = "function lwxFk(JJpsAlZhfTp,hndgIiOgStvNx,YopOkkxD){NoGG=XNUpogTuSpzOEKDta(JJpsAlZhfTp,hndgIiOgStvNx);mXIKY=NoGG.toString(YopOkkx" ascii
    $s7  = "function lwxFk(JJpsAlZhfTp,hndgIiOgStvNx,YopOkkxD){NoGG=XNUpogTuSpzOEKDta(JJpsAlZhfTp,hndgIiOgStvNx);mXIKY=NoGG.toString(YopOkkx" ascii
    $s8  = "function ldZNtPR(TFauisCoOcTynOtNBjLVXohlfMXXISfIZYSg) {return !XDvNubcFAmn(stlCvPZvuJMUjOv(TFauisCoOcTynOtNBjLVXohlfMXXISfIZYSg" ascii
    $s9  = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s10 = "function ldZNtPR(TFauisCoOcTynOtNBjLVXohlfMXXISfIZYSg) {return !XDvNubcFAmn(stlCvPZvuJMUjOv(TFauisCoOcTynOtNBjLVXohlfMXXISfIZYSg" ascii
    $s11 = "function vWxCfokcNucZfBi(tNpmURWotCQduXmWd,hIDCsiluLWoPHuAAYBybipAXvxnLvHoXKO,japGWfxiqrfHiqJRIrvtjnqbuvMzPiqeqJh){eval(tNpmURWo" ascii
    $s12 = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s13 = "D);return mXIKY;}" fullword ascii
    $s14 = "function XNUpogTuSpzOEKDta(fJUnEJAxJx,aLsWHfLYrv) {return parseInt(fJUnEJAxJx,aLsWHfLYrv);}" fullword ascii
    $s15 = "function I(KzULDvwSSTRI,nOiwHuXfhBskBf){KzULDvwSSTRI.push(nOiwHuXfhBskBf);}" fullword ascii
    $s16 = "function lFjjrNGLngsrlIeQgRKQJpONSqmkVeEBcRnDBarLyTcOqnRewCKJJV(bsvbcJAmWNzrc,TWIkSVocMJIAzI){ return eWHLHru[osWGmhPp[lwxFk(bsv" ascii
    $s17 = "function fJppXlNJzMwu(oImntQFvzArHN) {return isFinite(oImntQFvzArHN);}" fullword ascii
    $s18 = "function q(iALhITvYVdBHND,UYsTEoxkaIgkD,vvpodkyVRpE) {iALhITvYVdBHND[UYsTEoxkaIgkD]=vvpodkyVRpE;}" fullword ascii
    $s19 = "function lFjjrNGLngsrlIeQgRKQJpONSqmkVeEBcRnDBarLyTcOqnRewCKJJV(bsvbcJAmWNzrc,TWIkSVocMJIAzI){ return eWHLHru[osWGmhPp[lwxFk(bsv" ascii
    $s20 = "function XDvNubcFAmn(JoJHkICMgCvOmZ) {return isNaN(JoJHkICMgCvOmZ);}" fullword ascii

  condition:
    uint16(0) == 0x736f and
    8 of them
}