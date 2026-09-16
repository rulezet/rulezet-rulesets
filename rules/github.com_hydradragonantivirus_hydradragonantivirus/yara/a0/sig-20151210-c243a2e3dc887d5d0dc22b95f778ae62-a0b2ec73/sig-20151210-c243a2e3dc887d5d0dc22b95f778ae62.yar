rule sig_20151210_c243a2e3dc887d5d0dc22b95f778ae62 {
  meta:
    description = "datamaliciousorder - file 20151210_c243a2e3dc887d5d0dc22b95f778ae62.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7007ad3c97556a9bd9f6740c966077acad542a74c9ce673d7a44904afc19932"

  strings:
    $s1  = "function cURRhtT(TwpbhYZfmfujPncghfVXTUxHtHgluepSoNHW) {return !isNaN(parseFloat(TwpbhYZfmfujPncghfVXTUxHtHgluepSoNHW)) && isFin" ascii
    $s2  = "function cURRhtT(TwpbhYZfmfujPncghfVXTUxHtHgluepSoNHW) {return !isNaN(parseFloat(TwpbhYZfmfujPncghfVXTUxHtHgluepSoNHW)) && isFin" ascii
    $s3  = "function KOBTl(QUXGVpxKGUJ,ZcgHUHNxSbYTQ,RaZljFoE){LPpX=parseInt(QUXGVpxKGUJ,ZcgHUHNxSbYTQ);SqdrS=LPpX.toString(RaZljFoE);return" ascii
    $s4  = "PotcQqP=(-746+746)/945;while(true){if(PotcQqP>=(47355+389)/373){break;}wnmolBKVKdDda[PotcQqP]=String.fromCharCode(PotcQqP);PotcQ" ascii
    $s5  = "function zZajADqnerXwjefzf(nyFKN){HWYvlTnePbp= '';for(dhrPeluXLFB=(-199+199)/505; dhrPeluXLFB < (108+980)/544; dhrPeluXLFB++) {E" ascii
    $s6  = "function zZajADqnerXwjefzf(nyFKN){HWYvlTnePbp= '';for(dhrPeluXLFB=(-199+199)/505; dhrPeluXLFB < (108+980)/544; dhrPeluXLFB++) {E" ascii
    $s7  = "++;}} return HWYvlTnePbp}" fullword ascii
    $s8  = "function OyjUciqEGBj(EENNxTdv,kTsXrH){return EENNxTdv.split(kTsXrH)}" fullword ascii
    $s9  = "function KOBTl(QUXGVpxKGUJ,ZcgHUHNxSbYTQ,RaZljFoE){LPpX=parseInt(QUXGVpxKGUJ,ZcgHUHNxSbYTQ);SqdrS=LPpX.toString(RaZljFoE);return" ascii
    $s10 = "AIuJWNZj[dhrPeluXLFB]=(-224+224)/607; while(true) { if(EAIuJWNZj[dhrPeluXLFB] > nyFKN[dhrPeluXLFB].length-(265+561)/826) { break" ascii
    $s11 = "function LtGjPXPtNVOLQUEppwemLLHrOlSPmIaxNFKUIUUWnUPOqddqHZzwzr(gWBNIppdrnhtU,EKKgpWifKdtdmo){ return wnmolBKVKdDda[KOBTl(gWBNIp" ascii
    $s12 = " SqdrS;}function sGaYmqXwlamXmPE(yNInxPZFqCBrWsUzq){eval(yNInxPZFqCBrWsUzq)}" fullword ascii
    $s13 = "function LtGjPXPtNVOLQUEppwemLLHrOlSPmIaxNFKUIUUWnUPOqddqHZzwzr(gWBNIppdrnhtU,EKKgpWifKdtdmo){ return wnmolBKVKdDda[KOBTl(gWBNIp" ascii
    $s14 = "PotcQqP=(-746+746)/945;while(true){if(PotcQqP>=(47355+389)/373){break;}wnmolBKVKdDda[PotcQqP]=String.fromCharCode(PotcQqP);PotcQ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}