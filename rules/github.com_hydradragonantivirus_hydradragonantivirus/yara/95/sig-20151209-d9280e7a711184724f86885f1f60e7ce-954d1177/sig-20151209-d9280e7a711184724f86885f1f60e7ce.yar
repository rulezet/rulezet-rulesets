rule sig_20151209_d9280e7a711184724f86885f1f60e7ce {
  meta:
    description = "datamaliciousorder - file 20151209_d9280e7a711184724f86885f1f60e7ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0df7c151e1a2bfd54715c49f5fce3242eb51d07232f330f7cede214f1c73bafe"

  strings:
    $s1  = "function RShyxzT(htHPvaqHYcGgcoptqFdsaAURlclysJDXnSgJ) {return !isNaN(parseFloat(htHPvaqHYcGgcoptqFdsaAURlclysJDXnSgJ)) && isFin" ascii
    $s2  = "function RShyxzT(htHPvaqHYcGgcoptqFdsaAURlclysJDXnSgJ) {return !isNaN(parseFloat(htHPvaqHYcGgcoptqFdsaAURlclysJDXnSgJ)) && isFin" ascii
    $s3  = "function ABAjNlTcvNPnYeesR(ISvHi){xeKngZamLYD= '';for(pwDvuWwGGan=(-358+358)/655; pwDvuWwGGan < (55+179)/117; pwDvuWwGGan++) {Yq" ascii
    $s4  = "function IzQNe(mlrkSxMWAmM,vQiyrkucYtodz,birfGmHq){hmsq=parseInt(mlrkSxMWAmM,vQiyrkucYtodz);spwnm=hmsq.toString(birfGmHq);return" ascii
    $s5  = "function nJxwHziIyck(GPUBuDTu,nDCSEY){return GPUBuDTu.split(nDCSEY)}" fullword ascii
    $s6  = "function ABAjNlTcvNPnYeesR(ISvHi){xeKngZamLYD= '';for(pwDvuWwGGan=(-358+358)/655; pwDvuWwGGan < (55+179)/117; pwDvuWwGGan++) {Yq" ascii
    $s7  = " spwnm;}function ZScYXACtpaFAMne(JNnwVOaWnzuRgkAXG){eval(JNnwVOaWnzuRgkAXG)}" fullword ascii
    $s8  = "bSWqxwE[pwDvuWwGGan]=(-108+108)/299; while(true) { if(YqbSWqxwE[pwDvuWwGGan] > ISvHi[pwDvuWwGGan].length-(-303+988)/685) { break" ascii
    $s9  = "function gOZfsmvqVlKuGVeluLmvbLAHCGXQrkkUbLvIyXtfEsfBqUYAMvcxFN(StwhSEWUkvlKl,UvCVflgFjErrHN){ return qdekM[IzQNe(StwhSEWUkvlKl[" ascii
    $s10 = "function gOZfsmvqVlKuGVeluLmvbLAHCGXQrkkUbLvIyXtfEsfBqUYAMvcxFN(StwhSEWUkvlKl,UvCVflgFjErrHN){ return qdekM[IzQNe(StwhSEWUkvlKl[" ascii
    $s11 = "function IzQNe(mlrkSxMWAmM,vQiyrkucYtodz,birfGmHq){hmsq=parseInt(mlrkSxMWAmM,vQiyrkucYtodz);spwnm=hmsq.toString(birfGmHq);return" ascii
    $s12 = "+;}} return xeKngZamLYD}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}