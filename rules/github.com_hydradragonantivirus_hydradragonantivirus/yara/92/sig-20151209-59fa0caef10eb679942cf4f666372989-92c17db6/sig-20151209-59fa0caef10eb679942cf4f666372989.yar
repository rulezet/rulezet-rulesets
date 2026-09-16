rule sig_20151209_59fa0caef10eb679942cf4f666372989 {
  meta:
    description = "datamaliciousorder - file 20151209_59fa0caef10eb679942cf4f666372989.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9731f7f5a899a0100ed8a876bd78695f95270aa8b8368e67be404e21d2978b36"

  strings:
    $s1  = "function oQDlnyk(tJhzkhrYVJScdFkGtRiwsmNJoLuFxRrtXPJU) {return !isNaN(parseFloat(tJhzkhrYVJScdFkGtRiwsmNJoLuFxRrtXPJU)) && isFin" ascii
    $s2  = "function oQDlnyk(tJhzkhrYVJScdFkGtRiwsmNJoLuFxRrtXPJU) {return !isNaN(parseFloat(tJhzkhrYVJScdFkGtRiwsmNJoLuFxRrtXPJU)) && isFin" ascii
    $s3  = "function VMmRKuVfnhmcJGmhD(Cneag){ZrrYjaVWjRh= '';for(LwRNdEnVzKh=(-58+58)/424; LwRNdEnVzKh < (904+94)/499; LwRNdEnVzKh++) {fvil" ascii
    $s4  = "function kTCSsUhtOplqIsndMAXXLUUpUTBmpHBMTXQwMaUCLtGICtpLyPMhSC(aFTrwbIJMnAjv,GHkVjJxjcIRiYb){ return azzRf[wBRzL(aFTrwbIJMnAjv[" ascii
    $s5  = "function wBRzL(spcWTnkMjws,AKMNlCSpoTJRE,AoRvuRfm){fUmh=parseInt(spcWTnkMjws,AKMNlCSpoTJRE);fqxyS=fUmh.toString(AoRvuRfm);return" ascii
    $s6  = "turn ZrrYjaVWjRh}" fullword ascii
    $s7  = "function cnwshlRHxGl(AegVfGCd,OeyUYm){return AegVfGCd.split(OeyUYm)}" fullword ascii
    $s8  = "function kTCSsUhtOplqIsndMAXXLUUpUTBmpHBMTXQwMaUCLtGICtpLyPMhSC(aFTrwbIJMnAjv,GHkVjJxjcIRiYb){ return azzRf[wBRzL(aFTrwbIJMnAjv[" ascii
    $s9  = "function wBRzL(spcWTnkMjws,AKMNlCSpoTJRE,AoRvuRfm){fUmh=parseInt(spcWTnkMjws,AKMNlCSpoTJRE);fqxyS=fUmh.toString(AoRvuRfm);return" ascii
    $s10 = "function VMmRKuVfnhmcJGmhD(Cneag){ZrrYjaVWjRh= '';for(LwRNdEnVzKh=(-58+58)/424; LwRNdEnVzKh < (904+94)/499; LwRNdEnVzKh++) {fvil" ascii
    $s11 = "SlYcA[LwRNdEnVzKh]=(-499+499)/249; while(true) { if(fvilSlYcA[LwRNdEnVzKh] > Cneag[LwRNdEnVzKh].length-(-40+318)/278) { break; }" ascii
    $s12 = " fqxyS;}function PdkAyTrelrRePqv(tXlBbedCLSqWbVucA){eval(tXlBbedCLSqWbVucA)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}