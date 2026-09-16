rule sig_20151217_67dd74dd3f15049e10b08765e3711583 {
  meta:
    description = "datamaliciousorder - file 20151217_67dd74dd3f15049e10b08765e3711583.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8113f08d98f557fabc5bd05c86988374457b17128391c6e2106249cd55111dfe"

  strings:
    $s1  = ") - 1));while(true){if (uUPVwyReCNr >= (827+793)/270){break;}lCsWWWdMU[uUPVwyReCNr]=Math.round((Math.pow(Math.sin(243), 2) + Mat" ascii
    $s2  = "function NNmlNextGiqPQYxGw(VBggt){eLIXmOcpRtS= '';uUPVwyReCNr=Math.round((Math.pow(Math.sin(288), 2) + Math.pow(Math.cos(288), 2" ascii
    $s3  = "h.pow(Math.cos(243), 2) - 1)); while(true) { if(lCsWWWdMU[uUPVwyReCNr] > VBggt[uUPVwyReCNr].length-(402+326)/728) { break; } if " ascii
    $s4  = "(Math.cos(22), 2) - 1)));} lCsWWWdMU[uUPVwyReCNr]++;}uUPVwyReCNr++;} return eLIXmOcpRtS}" fullword ascii
    $s5  = "function NNmlNextGiqPQYxGw(VBggt){eLIXmOcpRtS= '';uUPVwyReCNr=Math.round((Math.pow(Math.sin(288), 2) + Math.pow(Math.cos(288), 2" ascii
    $s6  = "function bXcGoBH(TLJwIPnKEwmOrDMuHUqLtthtIoKpzimuYIVy) {return !KxTOCFtNUIJ(ONAqQDiPiDGjAxv(TLJwIPnKEwmOrDMuHUqLtthtIoKpzimuYIVy" ascii
    $s7  = "function t(YfgcmdNbMHLM,xsvLGwboeiKuSQ){YfgcmdNbMHLM.push(xsvLGwboeiKuSQ);}" fullword ascii
    $s8  = "var n = new Array();n[0]=[];n[0][0]='d';n[0][1]='a';n[0][2]='d';n[0][3]='a';n[0][4]='46';n[0][5]='3d';n[0][6]='42';n[0][7]='14';" ascii
    $s9  = "function hhBPe(UpUmpAlgRUP,ICrtFCOrQacQY,JXWgthzA){zkDA=HXAuIpjlpXLBUUoYk(UpUmpAlgRUP,ICrtFCOrQacQY);DGZQc=zkDA.toString(JXWgthz" ascii
    $s10 = "function VRBbnFvBXOkPeCS(WwDTOQqyPCgfLdfsB,azObYzIFTRpgkcnuIeNEGVRDndqASEoglH,OkUoogMRCnWSFsTNYOCQuNHacvMOHCNnSAa){eval(WwDTOQqy" ascii
    $s11 = "function zfhbCDWVDnKd(GNfHUfsaiuSoS) {return isFinite(GNfHUfsaiuSoS);}" fullword ascii
    $s12 = "A);return DGZQc;}" fullword ascii
    $s13 = "function KxTOCFtNUIJ(OEajtqPHcPrvfX) {return isNaN(OEajtqPHcPrvfX);}" fullword ascii
    $s14 = "function hhBPe(UpUmpAlgRUP,ICrtFCOrQacQY,JXWgthzA){zkDA=HXAuIpjlpXLBUUoYk(UpUmpAlgRUP,ICrtFCOrQacQY);DGZQc=zkDA.toString(JXWgthz" ascii
    $s15 = "function VaMatipuBIiBftoivksFBEeRydZuWHqRHkjvTiYKRQAgWcHaBuHbCW(AgvUwkTdGrApy,DAvPWtNxnPXCHD){ return QtbPiqa[hKbgyyuY[hhBPe(Agv" ascii
    $s16 = "function VaMatipuBIiBftoivksFBEeRydZuWHqRHkjvTiYKRQAgWcHaBuHbCW(AgvUwkTdGrApy,DAvPWtNxnPXCHD){ return QtbPiqa[hKbgyyuY[hhBPe(Agv" ascii
    $s17 = "function HXAuIpjlpXLBUUoYk(OZcRQVEWpR,ygpNFdVvVT) {return parseInt(OZcRQVEWpR,ygpNFdVvVT);}" fullword ascii
    $s18 = "function VRBbnFvBXOkPeCS(WwDTOQqyPCgfLdfsB,azObYzIFTRpgkcnuIeNEGVRDndqASEoglH,OkUoogMRCnWSFsTNYOCQuNHacvMOHCNnSAa){eval(WwDTOQqy" ascii
    $s19 = "function bXcGoBH(TLJwIPnKEwmOrDMuHUqLtthtIoKpzimuYIVy) {return !KxTOCFtNUIJ(ONAqQDiPiDGjAxv(TLJwIPnKEwmOrDMuHUqLtthtIoKpzimuYIVy" ascii
    $s20 = "var n = new Array();n[0]=[];n[0][0]='d';n[0][1]='a';n[0][2]='d';n[0][3]='a';n[0][4]='46';n[0][5]='3d';n[0][6]='42';n[0][7]='14';" ascii

  condition:
    uint16(0) == 0x4b68 and
    8 of them
}