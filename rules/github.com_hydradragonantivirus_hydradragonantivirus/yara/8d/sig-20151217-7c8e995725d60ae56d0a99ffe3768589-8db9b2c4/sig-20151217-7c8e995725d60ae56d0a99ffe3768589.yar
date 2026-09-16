rule sig_20151217_7c8e995725d60ae56d0a99ffe3768589 {
  meta:
    description = "datamaliciousorder - file 20151217_7c8e995725d60ae56d0a99ffe3768589.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e25576def9c6ab9cbcfad0ba5988ceb900f994e787210c0f8df67e71d31b0a7b"

  strings:
    $s1  = "th.pow(Math.cos(324), 2) - 1)); while(true) { if(UaVwdGRet[DtvflpAVjKB] > qtMQb[DtvflpAVjKB].length-(-734+888)/154) { break; } i" ascii
    $s2  = ".pow(Math.cos(561), 2) - 1)));} UaVwdGRet[DtvflpAVjKB]++;}DtvflpAVjKB++;} return FvZuGLMTfvn}" fullword ascii
    $s3  = ") - 1));while(true){if (DtvflpAVjKB >= (2090+676)/461){break;}UaVwdGRet[DtvflpAVjKB]=Math.round((Math.pow(Math.sin(324), 2) + Ma" ascii
    $s4  = "function SQMRUuoAgrlPYKgyq(qtMQb){FvZuGLMTfvn= '';DtvflpAVjKB=Math.round((Math.pow(Math.sin(982), 2) + Math.pow(Math.cos(982), 2" ascii
    $s5  = "BXZKiKbePvQcEbWZsUIKYjsCjGvCJewRpYfL([qtMQb[DtvflpAVjKB][UaVwdGRet[DtvflpAVjKB]]], Math.round((Math.pow(Math.sin(561), 2) + Math" ascii
    $s6  = "function SQMRUuoAgrlPYKgyq(qtMQb){FvZuGLMTfvn= '';DtvflpAVjKB=Math.round((Math.pow(Math.sin(982), 2) + Math.pow(Math.cos(982), 2" ascii
    $s7  = "function ZOpCRCg(pxNwbTvZCMwyoemtjhhXFSleufSEqKmdEoMe) {return !OGbtbADznYF(isvIIJzAcFFOsaH(pxNwbTvZCMwyoemtjhhXFSleufSEqKmdEoMe" ascii
    $s8  = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s9  = "function RqxydKDIWiTvxklDn(YQeQsWawlk,uqDHURYTFu) {return parseInt(YQeQsWawlk,uqDHURYTFu);}" fullword ascii
    $s10 = "function Z(obQqVemJJRLY,MNeDSdimRkhhRC){obQqVemJJRLY.push(MNeDSdimRkhhRC);}" fullword ascii
    $s11 = "function lHBJo(VtonhWkoMdI,ozLnUHetMRQYO,DQTgPyPl){vnDY=RqxydKDIWiTvxklDn(VtonhWkoMdI,ozLnUHetMRQYO);NvfwE=vnDY.toString(DQTgPyP" ascii
    $s12 = "function lHBJo(VtonhWkoMdI,ozLnUHetMRQYO,DQTgPyPl){vnDY=RqxydKDIWiTvxklDn(VtonhWkoMdI,ozLnUHetMRQYO);NvfwE=vnDY.toString(DQTgPyP" ascii
    $s13 = "function NPOHKfXdkUCg(nLsTPeCwleMEr) {return isFinite(nLsTPeCwleMEr);}" fullword ascii
    $s14 = "function tgwxbiwQeGxGepXYanBXZKiKbePvQcEbWZsUIKYjsCjGvCJewRpYfL(GqTXRRpvdgqsc,DpamktHRfRXryD){ return ZWDgxsL[VHKGBkvD[lHBJo(GqT" ascii
    $s15 = "function tgwxbiwQeGxGepXYanBXZKiKbePvQcEbWZsUIKYjsCjGvCJewRpYfL(GqTXRRpvdgqsc,DpamktHRfRXryD){ return ZWDgxsL[VHKGBkvD[lHBJo(GqT" ascii
    $s16 = "function S(KCVrOpPXeXXEFa,SFzZfcmhpzStF,qfhZBFFLulQ) {KCVrOpPXeXXEFa[SFzZfcmhpzStF]=qfhZBFFLulQ;}" fullword ascii
    $s17 = "function isvIIJzAcFFOsaH(TSXQLxtilUNglRjtIPZ) {return parseFloat(TSXQLxtilUNglRjtIPZ);}" fullword ascii
    $s18 = "function OGbtbADznYF(jxstFiwIMoquST) {return isNaN(jxstFiwIMoquST);}" fullword ascii
    $s19 = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s20 = "function ZOpCRCg(pxNwbTvZCMwyoemtjhhXFSleufSEqKmdEoMe) {return !OGbtbADznYF(isvIIJzAcFFOsaH(pxNwbTvZCMwyoemtjhhXFSleufSEqKmdEoMe" ascii

  condition:
    uint16(0) == 0x4856 and
    8 of them
}