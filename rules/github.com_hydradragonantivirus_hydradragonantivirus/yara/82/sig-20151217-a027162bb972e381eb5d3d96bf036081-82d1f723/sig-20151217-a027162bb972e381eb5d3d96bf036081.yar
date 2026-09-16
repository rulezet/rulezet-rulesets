rule sig_20151217_a027162bb972e381eb5d3d96bf036081 {
  meta:
    description = "datamaliciousorder - file 20151217_a027162bb972e381eb5d3d96bf036081.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bd7d7e4689148ae2866b4165a6f54eb6f7920ad4b61b9e987b02f8996aa5aa9"

  strings:
    $s1  = "pow(Math.cos(718), 2) - 1)));} mTYmoKzkl[DGriyNsdgJc]++;}DGriyNsdgJc++;} return cxSFMgIdwjh}" fullword ascii
    $s2  = "th.pow(Math.cos(453), 2) - 1)); while(true) { if(mTYmoKzkl[DGriyNsdgJc] > BDRcj[DGriyNsdgJc].length-(365+463)/828) { break; } if" ascii
    $s3  = ") - 1));while(true){if (DGriyNsdgJc >= (1808+358)/361){break;}mTYmoKzkl[DGriyNsdgJc]=Math.round((Math.pow(Math.sin(453), 2) + Ma" ascii
    $s4  = "function CeBTffzQiJMTeqKey(BDRcj){cxSFMgIdwjh= '';DGriyNsdgJc=Math.round((Math.pow(Math.sin(554), 2) + Math.pow(Math.cos(554), 2" ascii
    $s5  = "function CeBTffzQiJMTeqKey(BDRcj){cxSFMgIdwjh= '';DGriyNsdgJc=Math.round((Math.pow(Math.sin(554), 2) + Math.pow(Math.cos(554), 2" ascii
    $s6  = "WLKRvSfnItEGNNdybWcagkeyCMqsmhyLDQZ([BDRcj[DGriyNsdgJc][mTYmoKzkl[DGriyNsdgJc]]], Math.round((Math.pow(Math.sin(718), 2) + Math." ascii
    $s7  = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s8  = "function X(ZNPMJqCoCYne,FRfXYzVzagyhUK){ZNPMJqCoCYne.push(FRfXYzVzagyhUK);}" fullword ascii
    $s9  = "function PAxpV(udDekPARrwN,BxAIsMUgdabBJ,myrHrLeZ){KuOU=nVinulXqjyqDxdVyu(udDekPARrwN,BxAIsMUgdabBJ);ZNBjO=KuOU.toString(myrHrLe" ascii
    $s10 = "function PAxpV(udDekPARrwN,BxAIsMUgdabBJ,myrHrLeZ){KuOU=nVinulXqjyqDxdVyu(udDekPARrwN,BxAIsMUgdabBJ);ZNBjO=KuOU.toString(myrHrLe" ascii
    $s11 = "function mjoCEHbAjDTsRPr(WwVOVUHDgHokycQYs,FqPerlqDYNURLbVOGUHmPHqABajeRONmMG,MwagCrEGNePxRoiCvnclNRdxNBnRkDEDAfC){eval(WwVOVUHD" ascii
    $s12 = "function v(OBPsrVWTuTruwp,ZeHAfEveqmJkl,BEArgJCsQJB) {OBPsrVWTuTruwp[ZeHAfEveqmJkl]=BEArgJCsQJB;}" fullword ascii
    $s13 = "Z);return ZNBjO;}" fullword ascii
    $s14 = "function DuGtnEkXLWL(RvvsMrBJIDVlyo) {return isNaN(RvvsMrBJIDVlyo);}" fullword ascii
    $s15 = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s16 = "function mjoCEHbAjDTsRPr(WwVOVUHDgHokycQYs,FqPerlqDYNURLbVOGUHmPHqABajeRONmMG,MwagCrEGNePxRoiCvnclNRdxNBnRkDEDAfC){eval(WwVOVUHD" ascii
    $s17 = "function rFTeChsvuApg(AkuQfckTQnOCN) {return isFinite(AkuQfckTQnOCN);}" fullword ascii
    $s18 = "function nVinulXqjyqDxdVyu(xIekIvTQcE,LiirdvCBdr) {return parseInt(xIekIvTQcE,LiirdvCBdr);}" fullword ascii
    $s19 = "function VxNBqJBGkjoIeMJImqcWLKRvSfnItEGNNdybWcagkeyCMqsmhyLDQZ(mnHAluIJFQUmI,EHBvWQabAHziOq){ return BqIMXtB[YmPrQUuW[PAxpV(mnH" ascii
    $s20 = "function WvDBrsb(HQWiSFGtrJWSHhGIqwKGZthIiTCgVxRLARso) {return !DuGtnEkXLWL(XotzrPUhcaLTwNs(HQWiSFGtrJWSHhGIqwKGZthIiTCgVxRLARso" ascii

  condition:
    uint16(0) == 0x6d59 and
    8 of them
}