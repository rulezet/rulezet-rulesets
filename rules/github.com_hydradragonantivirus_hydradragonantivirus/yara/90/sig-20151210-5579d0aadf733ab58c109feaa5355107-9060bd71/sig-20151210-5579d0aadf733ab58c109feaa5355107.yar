rule sig_20151210_5579d0aadf733ab58c109feaa5355107 {
  meta:
    description = "datamaliciousorder - file 20151210_5579d0aadf733ab58c109feaa5355107.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4064a2e6c939dc940b85353b9e8126dad961c30692b57e9b8b3e1d437e6f6cc"

  strings:
    $s1  = "function ssgDJjL(pawujfCPKSqbfiDJaGVhEhSvsmUmXdGQuPlV) {return !isNaN(parseFloat(pawujfCPKSqbfiDJaGVhEhSvsmUmXdGQuPlV)) && isFin" ascii
    $s2  = "function ssgDJjL(pawujfCPKSqbfiDJaGVhEhSvsmUmXdGQuPlV) {return !isNaN(parseFloat(pawujfCPKSqbfiDJaGVhEhSvsmUmXdGQuPlV)) && isFin" ascii
    $s3  = " VroNW;}function DogSrHNEoXceSGO(dumztlihiFwUMSusy){eval(dumztlihiFwUMSusy)}" fullword ascii
    $s4  = "function mrneIurnMfF(VXvLIshF,WKsjIS){return VXvLIshF.split(WKsjIS)}" fullword ascii
    $s5  = "function JxKkd(pAioCqpBHwa,VdspFNoUgapMF,XYGDieaE){aaKk=parseInt(pAioCqpBHwa,VdspFNoUgapMF);VroNW=aaKk.toString(XYGDieaE);return" ascii
    $s6  = "vSUoIMR[NoXIwzKmYve]=(-21+21)/265; while(true) { if(lJvSUoIMR[NoXIwzKmYve] > FvwsD[NoXIwzKmYve].length-(-634+777)/143) { break; " ascii
    $s7  = "function hiVbBndWrShjtptVYTqmhSCKvuULjUMQEdiWYbEShIHafbAUAlXPjF(tEKHEYNbOwXAu,RBlbjIMCXxpBVi){ return NaWdxtTlBjDWR[JxKkd(tEKHEY" ascii
    $s8  = "function hiVbBndWrShjtptVYTqmhSCKvuULjUMQEdiWYbEShIHafbAUAlXPjF(tEKHEYNbOwXAu,RBlbjIMCXxpBVi){ return NaWdxtTlBjDWR[JxKkd(tEKHEY" ascii
    $s9  = "function NMCNbcsvFDyetiSxA(FvwsD){WhmHqUTJblS= '';for(NoXIwzKmYve=(-59+59)/471; NoXIwzKmYve < (1304+168)/736; NoXIwzKmYve++) {lJ" ascii
    $s10 = "GlatJtU=(-794+794)/99;while(true){if(GlatJtU>=(26729+919)/216){break;}NaWdxtTlBjDWR[GlatJtU]=String.fromCharCode(GlatJtU);GlatJt" ascii
    $s11 = "function NMCNbcsvFDyetiSxA(FvwsD){WhmHqUTJblS= '';for(NoXIwzKmYve=(-59+59)/471; NoXIwzKmYve < (1304+168)/736; NoXIwzKmYve++) {lJ" ascii
    $s12 = "GlatJtU=(-794+794)/99;while(true){if(GlatJtU>=(26729+919)/216){break;}NaWdxtTlBjDWR[GlatJtU]=String.fromCharCode(GlatJtU);GlatJt" ascii
    $s13 = "}} return WhmHqUTJblS}" fullword ascii
    $s14 = "function JxKkd(pAioCqpBHwa,VdspFNoUgapMF,XYGDieaE){aaKk=parseInt(pAioCqpBHwa,VdspFNoUgapMF);VroNW=aaKk.toString(XYGDieaE);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}