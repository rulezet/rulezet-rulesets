rule sig_20151216_22fffa364a19b61eef1d557d52823990 {
  meta:
    description = "datamaliciousorder - file 20151216_22fffa364a19b61eef1d557d52823990.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4dd6123d3f951bced698dd1c1b424611cb20843d64522a06787cdb350b6979b"

  strings:
    $s1  = "function xIoNppWQjLxWFXoWk(cMqbW){AhmUYBsMVzb= '';OccUFkdzXhd=Math.round((Math.pow(Math.sin(534), 2) + Math.pow(Math.cos(534), 2" ascii
    $s2  = "th.pow(Math.cos(255), 2) - 1)); while(true) { if(HYmDEAIoR[OccUFkdzXhd] > cMqbW[OccUFkdzXhd].length-(136+479)/615) { break; } if" ascii
    $s3  = "pow(Math.cos(990), 2) - 1)));} HYmDEAIoR[OccUFkdzXhd]++;}OccUFkdzXhd++;} return AhmUYBsMVzb}" fullword ascii
    $s4  = ") - 1));while(true){if (OccUFkdzXhd >= (4674+636)/885){break;}HYmDEAIoR[OccUFkdzXhd]=Math.round((Math.pow(Math.sin(255), 2) + Ma" ascii
    $s5  = "FPAGmMvtMgrjWMuxyfLdInvCmdjHeAWkhxT([cMqbW[OccUFkdzXhd][HYmDEAIoR[OccUFkdzXhd]]], Math.round((Math.pow(Math.sin(990), 2) + Math." ascii
    $s6  = "function xIoNppWQjLxWFXoWk(cMqbW){AhmUYBsMVzb= '';OccUFkdzXhd=Math.round((Math.pow(Math.sin(534), 2) + Math.pow(Math.cos(534), 2" ascii
    $s7  = "function sncLUoo(NZldmYaLRsWMDVLBBaXAZmUZfaVVgGIlvAOO) {return !jTzjnKruUtN(jqBQBSFbZAfGnvp(NZldmYaLRsWMDVLBBaXAZmUZfaVVgGIlvAOO" ascii
    $s8  = "function nWgFmIrlYJVoFTbtTQPFPAGmMvtMgrjWMuxyfLdInvCmdjHeAWkhxT(dvLmsApQJZJAR,dubkRlWUiWfvWJ){ return KcpLXoJ[GkERcgKc[UKznG(dvL" ascii
    $s9  = "function nWgFmIrlYJVoFTbtTQPFPAGmMvtMgrjWMuxyfLdInvCmdjHeAWkhxT(dvLmsApQJZJAR,dubkRlWUiWfvWJ){ return KcpLXoJ[GkERcgKc[UKznG(dvL" ascii
    $s10 = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s11 = "function yFhedcKfOJYxwkFwS(NUMdiQLkcF,pfIyykdgBM) {return parseInt(NUMdiQLkcF,pfIyykdgBM);}" fullword ascii
    $s12 = "function c(pbgsZULlbJgaUd,GbDSBVuYAcbIJ,ryqOUkFWOix) {pbgsZULlbJgaUd[GbDSBVuYAcbIJ]=ryqOUkFWOix;}" fullword ascii
    $s13 = "function B(cZHaRwqGGvxP,lYsxvQjRgSPaGw){cZHaRwqGGvxP.push(lYsxvQjRgSPaGw);}" fullword ascii
    $s14 = "function YTVBtPqqXyOYQIb(UqyvkFKbpbmZSOHKv,XYrXnpQeXBPPmDlmfthGejRsXmUzhNcrNK,vRNJjTPuqyGWuDcpypLeNqppZZFaCzPlbAh){eval(UqyvkFKb" ascii
    $s15 = "e);return FGiwa;}" fullword ascii
    $s16 = "function UKznG(aZwxLWNVZcO,DqMWkeGfsNqHh,cemzjkXe){SSoM=yFhedcKfOJYxwkFwS(aZwxLWNVZcO,DqMWkeGfsNqHh);FGiwa=SSoM.toString(cemzjkX" ascii
    $s17 = "function sAzvagadNQkZ(XJbhpSxXBpXWk) {return isFinite(XJbhpSxXBpXWk);}" fullword ascii
    $s18 = "function YTVBtPqqXyOYQIb(UqyvkFKbpbmZSOHKv,XYrXnpQeXBPPmDlmfthGejRsXmUzhNcrNK,vRNJjTPuqyGWuDcpypLeNqppZZFaCzPlbAh){eval(UqyvkFKb" ascii
    $s19 = "function sncLUoo(NZldmYaLRsWMDVLBBaXAZmUZfaVVgGIlvAOO) {return !jTzjnKruUtN(jqBQBSFbZAfGnvp(NZldmYaLRsWMDVLBBaXAZmUZfaVVgGIlvAOO" ascii
    $s20 = "function jqBQBSFbZAfGnvp(yTqJCUvBCymOYfWqCfZ) {return parseFloat(yTqJCUvBCymOYfWqCfZ);}" fullword ascii

  condition:
    uint16(0) == 0x6b47 and
    8 of them
}