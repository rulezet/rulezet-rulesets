rule sig_20151216_a0b30f24d49d59c8d5cf479a3cbc5623 {
  meta:
    description = "datamaliciousorder - file 20151216_a0b30f24d49d59c8d5cf479a3cbc5623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a2ec335c3a17cb1a7d2909f61b3a0f4dddd065d85b21dc03e5ce7ba6170f38"

  strings:
    $s1  = "(Math.cos(646), 2) - 1)));} OmmYCPfcm[KKoHcNaXNeB]++;}KKoHcNaXNeB++;} return NJqKHgwhiJN}" fullword ascii
    $s2  = "h.pow(Math.cos(274), 2) - 1)); while(true) { if(OmmYCPfcm[KKoHcNaXNeB] > ufrXG[KKoHcNaXNeB].length-(359+101)/460) { break; } if " ascii
    $s3  = ") - 1));while(true){if (KKoHcNaXNeB >= (4584+84)/778){break;}OmmYCPfcm[KKoHcNaXNeB]=Math.round((Math.pow(Math.sin(274), 2) + Mat" ascii
    $s4  = "function hIyoZHYcixDmhfLKo(ufrXG){NJqKHgwhiJN= '';KKoHcNaXNeB=Math.round((Math.pow(Math.sin(609), 2) + Math.pow(Math.cos(609), 2" ascii
    $s5  = "function hIyoZHYcixDmhfLKo(ufrXG){NJqKHgwhiJN= '';KKoHcNaXNeB=Math.round((Math.pow(Math.sin(609), 2) + Math.pow(Math.cos(609), 2" ascii
    $s6  = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s7  = "function PzAsK(puvVQokCTGt,tfVBOxNpBKDQV,WgPztbgB){FeDv=XDsDFtVALNAwYfCqT(puvVQokCTGt,tfVBOxNpBKDQV);omMmP=FeDv.toString(WgPztbg" ascii
    $s8  = "function PzAsK(puvVQokCTGt,tfVBOxNpBKDQV,WgPztbgB){FeDv=XDsDFtVALNAwYfCqT(puvVQokCTGt,tfVBOxNpBKDQV);omMmP=FeDv.toString(WgPztbg" ascii
    $s9  = "function o(FiPISICHCuWI,MTbmeyljIFAzfV){FiPISICHCuWI.push(MTbmeyljIFAzfV);}" fullword ascii
    $s10 = "function XDsDFtVALNAwYfCqT(cfsWOljmfh,kaGMHEcMuL) {return parseInt(cfsWOljmfh,kaGMHEcMuL);}" fullword ascii
    $s11 = "function UHxtGdbsbFnp(ZsmBAHlZHaOeH) {return isFinite(ZsmBAHlZHaOeH);}" fullword ascii
    $s12 = "function FjGZpwJBqUpybSP(lTsSCROPdFMxlNAGN,nSbumhxnoquTeMxQSgXmixNwcoiApLxxty,FzGPVDhsJqeOFhNwwpALNbzxGyQSOyBoYUz){eval(lTsSCROP" ascii
    $s13 = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s14 = "B);return omMmP;}" fullword ascii
    $s15 = "function S(qqQBUTieNTevqa,PlhshOzyVgOHU,xQhFdUxClnD) {qqQBUTieNTevqa[PlhshOzyVgOHU]=xQhFdUxClnD;}" fullword ascii
    $s16 = "function YXNAicDFcbu(btbDejSkKfMUke) {return isNaN(btbDejSkKfMUke);}" fullword ascii
    $s17 = "function FjGZpwJBqUpybSP(lTsSCROPdFMxlNAGN,nSbumhxnoquTeMxQSgXmixNwcoiApLxxty,FzGPVDhsJqeOFhNwwpALNbzxGyQSOyBoYUz){eval(lTsSCROP" ascii
    $s18 = "function JefvDVO(NslekotAboQyMvQkBImONbtXLTsFyyONjSUx) {return !YXNAicDFcbu(CBZdkcabpuwnhrA(NslekotAboQyMvQkBImONbtXLTsFyyONjSUx" ascii
    $s19 = "function CBZdkcabpuwnhrA(mVRuBFSHumdIybebRZb) {return parseFloat(mVRuBFSHumdIybebRZb);}" fullword ascii
    $s20 = "function BpiEssWSyIDNKkbtfRlTECAKUKfbGEDrgpJfbffOJxnTryZrVzJVWZ(jPZORaFmIHxRY,tyiawWSpFBpEjq){ return TJvsNHZ[bhilOUDF[PzAsK(jPZ" ascii

  condition:
    uint16(0) == 0x6862 and
    8 of them
}