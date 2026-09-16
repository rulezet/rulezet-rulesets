rule sig_20151209_f8a295b2f80838bae17af497970ecd97 {
  meta:
    description = "datamaliciousorder - file 20151209_f8a295b2f80838bae17af497970ecd97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "823acadd5d7e80c1013afd996c888e729e817a40b4e9855e22aa163e705889a7"

  strings:
    $s1  = "function jjEckIK(CHxgUMlkGiOPgyPZFqAkhyDaPOGqdxfEoZtP) {return !isNaN(parseFloat(CHxgUMlkGiOPgyPZFqAkhyDaPOGqdxfEoZtP)) && isFin" ascii
    $s2  = "function jjEckIK(CHxgUMlkGiOPgyPZFqAkhyDaPOGqdxfEoZtP) {return !isNaN(parseFloat(CHxgUMlkGiOPgyPZFqAkhyDaPOGqdxfEoZtP)) && isFin" ascii
    $s3  = "function raiQFhEYpFwWdsFdk(uJKpu){SsbDMwDqxun= '';for(hXweRJPwdXt=(-827+827)/570; hXweRJPwdXt < (108+688)/398; hXweRJPwdXt++) {t" ascii
    $s4  = "function raiQFhEYpFwWdsFdk(uJKpu){SsbDMwDqxun= '';for(hXweRJPwdXt=(-827+827)/570; hXweRJPwdXt < (108+688)/398; hXweRJPwdXt++) {t" ascii
    $s5  = "flFoUsJZ[hXweRJPwdXt]=(-788+788)/686; while(true) { if(tflFoUsJZ[hXweRJPwdXt] > uJKpu[hXweRJPwdXt].length-(414+69)/483) { break;" ascii
    $s6  = "function cptDVBaYXVQtcvInCGgyuEHtawznORdCTSsZmqPeWpYNmkcgAagbmF(uBRSpPPjZhAcY,rTAeYBcMGzWOIh){ return hNZhx[GZmnz(uBRSpPPjZhAcY[" ascii
    $s7  = "function GZmnz(uFOpAudiqbc,BXQzAncqDwcmo,iKowKspg){diRY=parseInt(uFOpAudiqbc,BXQzAncqDwcmo);AhNju=diRY.toString(iKowKspg);return" ascii
    $s8  = "function GZmnz(uFOpAudiqbc,BXQzAncqDwcmo,iKowKspg){diRY=parseInt(uFOpAudiqbc,BXQzAncqDwcmo);AhNju=diRY.toString(iKowKspg);return" ascii
    $s9  = "function MBsDBloHtlE(zAxCLUdf,ljnSfG){return zAxCLUdf.split(ljnSfG)}" fullword ascii
    $s10 = " AhNju;}function vvoEPVuVufPSYJw(HqNJOfvjYXittaLjk){eval(HqNJOfvjYXittaLjk)}" fullword ascii
    $s11 = "function cptDVBaYXVQtcvInCGgyuEHtawznORdCTSsZmqPeWpYNmkcgAagbmF(uBRSpPPjZhAcY,rTAeYBcMGzWOIh){ return hNZhx[GZmnz(uBRSpPPjZhAcY[" ascii
    $s12 = "}} return SsbDMwDqxun}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}