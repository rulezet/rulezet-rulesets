rule sig_20151209_2648d6022adaa41d33e8665c744dbcae {
  meta:
    description = "datamaliciousorder - file 20151209_2648d6022adaa41d33e8665c744dbcae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f997b5a4fd48a5a043ffdf9f6f3e41146da337cc22d9e9a8a9329f74f0413252"

  strings:
    $s1  = "function lqNoVCg(nPXUcICVIvEkShWQUPRRlcKvgINUSMeOtiPW) {return !isNaN(parseFloat(nPXUcICVIvEkShWQUPRRlcKvgINUSMeOtiPW)) && isFin" ascii
    $s2  = "function lqNoVCg(nPXUcICVIvEkShWQUPRRlcKvgINUSMeOtiPW) {return !isNaN(parseFloat(nPXUcICVIvEkShWQUPRRlcKvgINUSMeOtiPW)) && isFin" ascii
    $s3  = " PWlCH;}function KBbjHiWEMFSTwPD(VTYnboNuYzBXJGpOU){eval(VTYnboNuYzBXJGpOU)}" fullword ascii
    $s4  = ";}} return LxghqeUmVhG}" fullword ascii
    $s5  = "function clNJgaXDvggTWWUkv(wpJQX){LxghqeUmVhG= '';for(laKETMlrdCC=(-493+493)/345; laKETMlrdCC < (1379+157)/768; laKETMlrdCC++) {" ascii
    $s6  = "function RHLRNvvBcUG(Vxephgfn,ERjCOu){return Vxephgfn.split(ERjCOu)}" fullword ascii
    $s7  = "function jXuzt(tvpcqNZvEXW,vcVusCtIARHsO,aRBMnvTW){JDlZ=parseInt(tvpcqNZvEXW,vcVusCtIARHsO);PWlCH=JDlZ.toString(aRBMnvTW);return" ascii
    $s8  = "function jXuzt(tvpcqNZvEXW,vcVusCtIARHsO,aRBMnvTW){JDlZ=parseInt(tvpcqNZvEXW,vcVusCtIARHsO);PWlCH=JDlZ.toString(aRBMnvTW);return" ascii
    $s9  = "function QaqoEjdLETcUZSmMhIGDhroFSGUOAerftumBEHLFUuwpKTuxweKfDT(ktOgTyBlsjQnN,KjMRmnqNbJlpmO){ return KlXLU[jXuzt(ktOgTyBlsjQnN[" ascii
    $s10 = "function clNJgaXDvggTWWUkv(wpJQX){LxghqeUmVhG= '';for(laKETMlrdCC=(-493+493)/345; laKETMlrdCC < (1379+157)/768; laKETMlrdCC++) {" ascii
    $s11 = "VwXYRxorx[laKETMlrdCC]=(-193+193)/644; while(true) { if(VwXYRxorx[laKETMlrdCC] > wpJQX[laKETMlrdCC].length-(5+911)/916) { break;" ascii
    $s12 = "function QaqoEjdLETcUZSmMhIGDhroFSGUOAerftumBEHLFUuwpKTuxweKfDT(ktOgTyBlsjQnN,KjMRmnqNbJlpmO){ return KlXLU[jXuzt(ktOgTyBlsjQnN[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}