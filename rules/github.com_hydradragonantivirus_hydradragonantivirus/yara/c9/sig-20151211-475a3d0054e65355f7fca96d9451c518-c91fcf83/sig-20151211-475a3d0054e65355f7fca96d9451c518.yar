rule sig_20151211_475a3d0054e65355f7fca96d9451c518 {
  meta:
    description = "datamaliciousorder - file 20151211_475a3d0054e65355f7fca96d9451c518.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6593b0d037f1e909f8b3a2166a326b287026f5c4f735488f36d96adac3e577c"

  strings:
    $s1  = "FJREYejX[WosuMhrFidp]=(-859+859)/8; while(true) { if(NFJREYejX[WosuMhrFidp] > AlDdn[WosuMhrFidp].length-(605+12)/617) { break; }" ascii
    $s2  = "function uCHSxIt(aIZqrbCSLHymLvROoeOnvgbPChPGMRevcXWM) {return !isNaN(parseFloat(aIZqrbCSLHymLvROoeOnvgbPChPGMRevcXWM)) && isFin" ascii
    $s3  = "function uCHSxIt(aIZqrbCSLHymLvROoeOnvgbPChPGMRevcXWM) {return !isNaN(parseFloat(aIZqrbCSLHymLvROoeOnvgbPChPGMRevcXWM)) && isFin" ascii
    $s4  = "function YQHlEXjVxFlDdKsRY(AlDdn){qSgCYhzogis= '';WosuMhrFidp=(-455+455)/632; while(true){if(WosuMhrFidp >= (92+808)/450)break;N" ascii
    $s5  = "function YQHlEXjVxFlDdKsRY(AlDdn){qSgCYhzogis= '';WosuMhrFidp=(-455+455)/632; while(true){if(WosuMhrFidp >= (92+808)/450)break;N" ascii
    $s6  = "var n=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"44\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s7  = " GrYxs;}function BbFYIeiKNNKEjbL(smKZJsTJShGrXxCGC){eval(smKZJsTJShGrXxCGC)}" fullword ascii
    $s8  = "function FwnpNzkoOEJ(tDwSnFlZ,WIQZhB){return tDwSnFlZ.split(WIQZhB)}" fullword ascii
    $s9  = "function pZTtD(xXOWjntNTlr,GUQzxektZcsuX,vPxgAULI){FVzi=parseInt(xXOWjntNTlr,GUQzxektZcsuX);GrYxs=FVzi.toString(vPxgAULI);return" ascii
    $s10 = "}WosuMhrFidp++;} return qSgCYhzogis}" fullword ascii
    $s11 = "var f=new Array(\"2e\",\"2b\",\"29\",\"2a\",\"2e\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s12 = "function pZTtD(xXOWjntNTlr,GUQzxektZcsuX,vPxgAULI){FVzi=parseInt(xXOWjntNTlr,GUQzxektZcsuX);GrYxs=FVzi.toString(vPxgAULI);return" ascii
    $s13 = "var f=new Array(\"2e\",\"2b\",\"29\",\"2a\",\"2e\",\"26\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s14 = "var n=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"44\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s15 = "function dFCjiHjccAsLPVCidsVHKVZhLSDzkicUkwSWadSIZsOMPGlKPYSPDP(QROcFcSTGTSPD,KVtXxSdFXFhyuO){ return nbEOy[pZTtD(QROcFcSTGTSPD[" ascii
    $s16 = "function dFCjiHjccAsLPVCidsVHKVZhLSDzkicUkwSWadSIZsOMPGlKPYSPDP(QROcFcSTGTSPD,KVtXxSdFXFhyuO){ return nbEOy[pZTtD(QROcFcSTGTSPD[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}