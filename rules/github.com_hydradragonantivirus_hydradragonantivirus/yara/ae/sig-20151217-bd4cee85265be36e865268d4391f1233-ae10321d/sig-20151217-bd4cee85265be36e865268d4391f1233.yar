rule sig_20151217_bd4cee85265be36e865268d4391f1233 {
  meta:
    description = "datamaliciousorder - file 20151217_bd4cee85265be36e865268d4391f1233.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a765bf599e8b32f47ae40444237af4a95b3f5393a2393d6aa3a5d0bf8afd535a"

  strings:
    $s1  = "ow(Math.cos(303), 2) - 1)));} GFwrpILGl[SevacUybsND]++;}SevacUybsND++;} return bSklIzPSrOX}" fullword ascii
    $s2  = ") - 1));while(true){if (SevacUybsND >= (893+727)/270){break;}GFwrpILGl[SevacUybsND]=Math.round((Math.pow(Math.sin(778), 2) + Mat" ascii
    $s3  = "h.pow(Math.cos(778), 2) - 1)); while(true) { if(GFwrpILGl[SevacUybsND] > gQOdv[SevacUybsND].length-(136+819)/955) { break; } if " ascii
    $s4  = "function EqPXugoMkCaUiurZq(gQOdv){bSklIzPSrOX= '';SevacUybsND=Math.round((Math.pow(Math.sin(680), 2) + Math.pow(Math.cos(680), 2" ascii
    $s5  = "function XQeVmgy(WBJYxtbnVKoxLVYkuQIODqUUmhhvSEakkGBb) {return !PHHhedkPhDO(RCypbQFISYnJmGJ(WBJYxtbnVKoxLVYkuQIODqUUmhhvSEakkGBb" ascii
    $s6  = "function EqPXugoMkCaUiurZq(gQOdv){bSklIzPSrOX= '';SevacUybsND=Math.round((Math.pow(Math.sin(680), 2) + Math.pow(Math.cos(680), 2" ascii
    $s7  = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s8  = "function WyrEd(jslOjiVyXnd,rJXjXjuZnOKOJ,paADJZsL){vITO=aUonkLNjajcnxQKEU(jslOjiVyXnd,rJXjXjuZnOKOJ);Nxbvv=vITO.toString(paADJZs" ascii
    $s9  = "var L = new Array();L[0]=[];L[0][0]='d';L[0][1]='a';L[0][2]='d';L[0][3]='a';L[0][4]='46';L[0][5]='3d';L[0][6]='42';L[0][7]='14';" ascii
    $s10 = "function V(PFKMwfChKamAfC,FbmVKJQEUWFKZ,WkKEaJAyKOv) {PFKMwfChKamAfC[FbmVKJQEUWFKZ]=WkKEaJAyKOv;}" fullword ascii
    $s11 = "function IAvDZzihWJOe(GHgiGfVsiCGMv) {return isFinite(GHgiGfVsiCGMv);}" fullword ascii
    $s12 = "function XQeVmgy(WBJYxtbnVKoxLVYkuQIODqUUmhhvSEakkGBb) {return !PHHhedkPhDO(RCypbQFISYnJmGJ(WBJYxtbnVKoxLVYkuQIODqUUmhhvSEakkGBb" ascii
    $s13 = "function OXXAQFYGYsZduzTSbrXtHbQfqBTXDsTpnEhaqfkQgmPLeDkamLDwRj(jHyQBBlFSrqNe,MGhwGXZbKrSWaV){ return ExGQMyq[QtXnixgE[WyrEd(jHy" ascii
    $s14 = "function aUonkLNjajcnxQKEU(lSqZKrrMLP,fTiJuvEvBW) {return parseInt(lSqZKrrMLP,fTiJuvEvBW);}" fullword ascii
    $s15 = "function bBKAtuTSqTownZD(FLFPoXfARoLmIEMuD,CvnQBZFzemhmRmyNObRLmCQHmMSBNlmPCT,HzajrXVjmURXYKrOzsdJjgXhixfcebGtGBl){eval(FLFPoXfA" ascii
    $s16 = "function OXXAQFYGYsZduzTSbrXtHbQfqBTXDsTpnEhaqfkQgmPLeDkamLDwRj(jHyQBBlFSrqNe,MGhwGXZbKrSWaV){ return ExGQMyq[QtXnixgE[WyrEd(jHy" ascii
    $s17 = "L);return Nxbvv;}" fullword ascii
    $s18 = "function RCypbQFISYnJmGJ(OzDgvfagzKCJJPDIUIZ) {return parseFloat(OzDgvfagzKCJJPDIUIZ);}" fullword ascii
    $s19 = "function PHHhedkPhDO(yvNtAjgPAdnZAP) {return isNaN(yvNtAjgPAdnZAP);}" fullword ascii
    $s20 = "function bBKAtuTSqTownZD(FLFPoXfARoLmIEMuD,CvnQBZFzemhmRmyNObRLmCQHmMSBNlmPCT,HzajrXVjmURXYKrOzsdJjgXhixfcebGtGBl){eval(FLFPoXfA" ascii

  condition:
    uint16(0) == 0x7451 and
    8 of them
}