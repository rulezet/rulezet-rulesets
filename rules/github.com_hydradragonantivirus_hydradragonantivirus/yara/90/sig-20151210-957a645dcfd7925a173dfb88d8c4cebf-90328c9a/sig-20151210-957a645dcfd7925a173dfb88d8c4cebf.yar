rule sig_20151210_957a645dcfd7925a173dfb88d8c4cebf {
  meta:
    description = "datamaliciousorder - file 20151210_957a645dcfd7925a173dfb88d8c4cebf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83bbc900d8f8bb8d79916cd9427f4e48e9ed2be0a7a4a68d1538b53f16a026ef"

  strings:
    $s1  = "function thnqCZW(WzwoxFxjrjwEwmTJQlNCNCbcNKtPMugTZmnh) {return !isNaN(parseFloat(WzwoxFxjrjwEwmTJQlNCNCbcNKtPMugTZmnh)) && isFin" ascii
    $s2  = "function thnqCZW(WzwoxFxjrjwEwmTJQlNCNCbcNKtPMugTZmnh) {return !isNaN(parseFloat(WzwoxFxjrjwEwmTJQlNCNCbcNKtPMugTZmnh)) && isFin" ascii
    $s3  = "function snjqdCotJVKlKCgAxNcIyyPTJvfoDVGVDrGtSDiluuRoaJqhthcgeg(vSFjPhqUZeiFj,PrBQUHdroCYqiG){ return SeOGevDMwMbJm[uQLpR(vSFjPh" ascii
    $s4  = "MGMLWwi=(-47+47)/674;while(true){if(MGMLWwi>=(105763+605)/831){break;}SeOGevDMwMbJm[MGMLWwi]=String.fromCharCode(MGMLWwi);MGMLWw" ascii
    $s5  = "function HOoTnphykaCnmQRtB(ULMMM){MvHmfCgtFbC= '';for(BJHSbvDxkPt=(-987+987)/485; BJHSbvDxkPt < (1077+355)/716; BJHSbvDxkPt++) {" ascii
    $s6  = "function uQLpR(kOAIjLGMXjL,hvqEwqkAgqcQd,IZIpPdfD){qFHC=parseInt(kOAIjLGMXjL,hvqEwqkAgqcQd);yEKkF=qFHC.toString(IZIpPdfD);return" ascii
    $s7  = "function uQLpR(kOAIjLGMXjL,hvqEwqkAgqcQd,IZIpPdfD){qFHC=parseInt(kOAIjLGMXjL,hvqEwqkAgqcQd);yEKkF=qFHC.toString(IZIpPdfD);return" ascii
    $s8  = "eAyNAKZxD[BJHSbvDxkPt]=(-506+506)/375; while(true) { if(eAyNAKZxD[BJHSbvDxkPt] > ULMMM[BJHSbvDxkPt].length-(93+852)/945) { break" ascii
    $s9  = "function snjqdCotJVKlKCgAxNcIyyPTJvfoDVGVDrGtSDiluuRoaJqhthcgeg(vSFjPhqUZeiFj,PrBQUHdroCYqiG){ return SeOGevDMwMbJm[uQLpR(vSFjPh" ascii
    $s10 = "MGMLWwi=(-47+47)/674;while(true){if(MGMLWwi>=(105763+605)/831){break;}SeOGevDMwMbJm[MGMLWwi]=String.fromCharCode(MGMLWwi);MGMLWw" ascii
    $s11 = "}} return MvHmfCgtFbC}" fullword ascii
    $s12 = "function HOoTnphykaCnmQRtB(ULMMM){MvHmfCgtFbC= '';for(BJHSbvDxkPt=(-987+987)/485; BJHSbvDxkPt < (1077+355)/716; BJHSbvDxkPt++) {" ascii
    $s13 = " yEKkF;}function StgbjyrECHtCXtb(gzeweosoEDLauxDNZ){eval(gzeweosoEDLauxDNZ)}" fullword ascii
    $s14 = "function uYhcTMZswTy(ouvLdNtl,GXjCYy){return ouvLdNtl.split(GXjCYy)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}