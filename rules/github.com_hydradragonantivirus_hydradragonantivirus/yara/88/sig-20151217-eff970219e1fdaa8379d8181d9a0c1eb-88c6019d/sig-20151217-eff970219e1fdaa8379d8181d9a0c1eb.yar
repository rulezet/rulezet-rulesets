rule sig_20151217_eff970219e1fdaa8379d8181d9a0c1eb {
  meta:
    description = "datamaliciousorder - file 20151217_eff970219e1fdaa8379d8181d9a0c1eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3a09da6295d2beed0e4bc2d9b330e96415f770b0b7612b1b11536cc650c3ad9"

  strings:
    $s1  = ".pow(Math.cos(874), 2) - 1)); while(true) { if(SPREFMXeg[sxruruJJEdC] > IARvx[sxruruJJEdC].length-(235+40)/275) { break; } if (Q" ascii
    $s2  = "(Math.cos(542), 2) - 1)));} SPREFMXeg[sxruruJJEdC]++;}sxruruJJEdC++;} return iwvolzHzkwe}" fullword ascii
    $s3  = "function NHAAzCLeZrkXMAWYO(IARvx){iwvolzHzkwe= '';sxruruJJEdC=Math.round((Math.pow(Math.sin(85), 2) + Math.pow(Math.cos(85), 2) " ascii
    $s4  = "- 1));while(true){if (sxruruJJEdC >= (3626+502)/688){break;}SPREFMXeg[sxruruJJEdC]=Math.round((Math.pow(Math.sin(874), 2) + Math" ascii
    $s5  = "function NHAAzCLeZrkXMAWYO(IARvx){iwvolzHzkwe= '';sxruruJJEdC=Math.round((Math.pow(Math.sin(85), 2) + Math.pow(Math.cos(85), 2) " ascii
    $s6  = "function QsjWIdy(XYNUtaTmGPxJDFaZceOUzCLOzVebSoGtJOzN) {return !eJWWtJkOtIk(slcSgePIiDXQjKB(XYNUtaTmGPxJDFaZceOUzCLOzVebSoGtJOzN" ascii
    $s7  = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s8  = "function HHSVjioeqQhYMzgVY(wvMaTVguZP,DUPvYbMPuv) {return parseInt(wvMaTVguZP,DUPvYbMPuv);}" fullword ascii
    $s9  = "function slcSgePIiDXQjKB(ILBOtNqcNaRUWOuLpdT) {return parseFloat(ILBOtNqcNaRUWOuLpdT);}" fullword ascii
    $s10 = "function nmqrLeCOOYoE(EdwMGnHNZQxbn) {return isFinite(EdwMGnHNZQxbn);}" fullword ascii
    $s11 = "function eJWWtJkOtIk(MBUnFfjGhNxXZS) {return isNaN(MBUnFfjGhNxXZS);}" fullword ascii
    $s12 = "function XswLPZtifjdxTnnALFacGkNZAbctYdUVaVIpdULhTiJKInYUnfQEIk(OSKwqjNehrFRo,OhivrkCctlZLfH){ return gLhdEGH[arBubSyF[qLTYd(OSK" ascii
    $s13 = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s14 = "function olxsYRffcklnWsx(SUSEDfxmMCrqofPIr,vDksezmxYXTXXJfXlqlxXOWQAFRDFZpapZ,rAkogTJaNtgqUUDAcMrreRFtmHyDYhKiOgr){eval(SUSEDfxm" ascii
    $s15 = "function QsjWIdy(XYNUtaTmGPxJDFaZceOUzCLOzVebSoGtJOzN) {return !eJWWtJkOtIk(slcSgePIiDXQjKB(XYNUtaTmGPxJDFaZceOUzCLOzVebSoGtJOzN" ascii
    $s16 = "function T(oNHjDwVaGMIZ,oIYCJycivJjyPn){oNHjDwVaGMIZ.push(oIYCJycivJjyPn);}" fullword ascii
    $s17 = "function qLTYd(oXdUcGTXXGh,EldeEVBTFtauZ,WeriKpbX){aYJj=HHSVjioeqQhYMzgVY(oXdUcGTXXGh,EldeEVBTFtauZ);EZXkq=aYJj.toString(WeriKpb" ascii
    $s18 = "function qLTYd(oXdUcGTXXGh,EldeEVBTFtauZ,WeriKpbX){aYJj=HHSVjioeqQhYMzgVY(oXdUcGTXXGh,EldeEVBTFtauZ);EZXkq=aYJj.toString(WeriKpb" ascii
    $s19 = "function olxsYRffcklnWsx(SUSEDfxmMCrqofPIr,vDksezmxYXTXXJfXlqlxXOWQAFRDFZpapZ,rAkogTJaNtgqUUDAcMrreRFtmHyDYhKiOgr){eval(SUSEDfxm" ascii
    $s20 = "function XswLPZtifjdxTnnALFacGkNZAbctYdUVaVIpdULhTiJKInYUnfQEIk(OSKwqjNehrFRo,OhivrkCctlZLfH){ return gLhdEGH[arBubSyF[qLTYd(OSK" ascii

  condition:
    uint16(0) == 0x7261 and
    8 of them
}