rule sig_20151216_caf0e67ad3933668fa93e82bf4d2e53f {
  meta:
    description = "datamaliciousorder - file 20151216_caf0e67ad3933668fa93e82bf4d2e53f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "744933840e1438f49c7e5a3ecf860111b23df66c92b1add9c74f9cb1625d4a1a"

  strings:
    $s1  = "(Math.cos(740), 2) - 1)));} DniinTnSx[fEGqlIXPyzp]++;}fEGqlIXPyzp++;} return FliTpTFPpHj}" fullword ascii
    $s2  = "th.pow(Math.cos(438), 2) - 1)); while(true) { if(DniinTnSx[fEGqlIXPyzp] > SHGMt[fEGqlIXPyzp].length-(-282+884)/602) { break; } i" ascii
    $s3  = ") - 1));while(true){if (fEGqlIXPyzp >= (1458+756)/369){break;}DniinTnSx[fEGqlIXPyzp]=Math.round((Math.pow(Math.sin(438), 2) + Ma" ascii
    $s4  = "function aPzhcbUFtzKIuxrtK(SHGMt){FliTpTFPpHj= '';fEGqlIXPyzp=Math.round((Math.pow(Math.sin(533), 2) + Math.pow(Math.cos(533), 2" ascii
    $s5  = "function aPzhcbUFtzKIuxrtK(SHGMt){FliTpTFPpHj= '';fEGqlIXPyzp=Math.round((Math.pow(Math.sin(533), 2) + Math.pow(Math.cos(533), 2" ascii
    $s6  = "function lbtwSbZ(YaMKEyfnXYvZCcgPoGsmdheMyOiJDTTmsDtN) {return !GXIrZERWsgY(BbyZUlqtdfYeWAB(YaMKEyfnXYvZCcgPoGsmdheMyOiJDTTmsDtN" ascii
    $s7  = "function lbtwSbZ(YaMKEyfnXYvZCcgPoGsmdheMyOiJDTTmsDtN) {return !GXIrZERWsgY(BbyZUlqtdfYeWAB(YaMKEyfnXYvZCcgPoGsmdheMyOiJDTTmsDtN" ascii
    $s8  = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s9  = "function DNmSDhIErXtTcfJ(lWddznyoeulxckSXi,YuJJPQDPupZBexxdlUdrvbGUYrYbaqlEYI,OtHbYEBOWfdlgrqxHEiIPdHdneGncnVnxZM){eval(lWddznyo" ascii
    $s10 = "function GXIrZERWsgY(CBzpDEjwVfSVvj) {return isNaN(CBzpDEjwVfSVvj);}" fullword ascii
    $s11 = "function DNmSDhIErXtTcfJ(lWddznyoeulxckSXi,YuJJPQDPupZBexxdlUdrvbGUYrYbaqlEYI,OtHbYEBOWfdlgrqxHEiIPdHdneGncnVnxZM){eval(lWddznyo" ascii
    $s12 = "function TWzoxsffhvvs(quUrKPOoXegMo) {return isFinite(quUrKPOoXegMo);}" fullword ascii
    $s13 = "V);return BxzwW;}" fullword ascii
    $s14 = "function BbyZUlqtdfYeWAB(bfCGSRKKtzFiVOmqfgx) {return parseFloat(bfCGSRKKtzFiVOmqfgx);}" fullword ascii
    $s15 = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s16 = "function I(xZAFznktZpVPuD,RtZTqXDojwHME,SUKSCwiqZRZ) {xZAFznktZpVPuD[RtZTqXDojwHME]=SUKSCwiqZRZ;}" fullword ascii
    $s17 = "function yQcoHtYxEfHYnppbn(PySoKpauxR,btBqaJnPbF) {return parseInt(PySoKpauxR,btBqaJnPbF);}" fullword ascii
    $s18 = "function O(ESLaVTGwdRCc,mXOrLZoFCwdrEu){ESLaVTGwdRCc.push(mXOrLZoFCwdrEu);}" fullword ascii
    $s19 = "function BLMEb(ZcakUNDairq,CsByzWSCboKJF,yFTqtppV){fJfa=yQcoHtYxEfHYnppbn(ZcakUNDairq,CsByzWSCboKJF);BxzwW=fJfa.toString(yFTqtpp" ascii
    $s20 = "function VlpyfsmIFngRRlZyxdpWNScMgdUcwqupaAxZbdCANEvIqxRgOgYxDg(OOXnZIPAHvclM,PiiUVbjMMqpxwW){ return LJyLPuN[vnLTyQxm[BLMEb(OOX" ascii

  condition:
    uint16(0) == 0x6e76 and
    8 of them
}