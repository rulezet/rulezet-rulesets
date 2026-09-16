rule sig_20151217_8c3e974e9288aa39da2b3aafdd6d9f22 {
  meta:
    description = "datamaliciousorder - file 20151217_8c3e974e9288aa39da2b3aafdd6d9f22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28ff186ca427f76cd2ad96325fb13ed4c24cc623b6cb3ea1538e2a2ddb07b075"

  strings:
    $s1  = "function rxdaBkiYURxsQVLpQ(lesyj){IdUzkRoiMRf= '';YZxmpuCbwKC=Math.round((Math.pow(Math.sin(766), 2) + Math.pow(Math.cos(766), 2" ascii
    $s2  = "ow(Math.cos(565), 2) - 1)));} tyuEUAmQj[YZxmpuCbwKC]++;}YZxmpuCbwKC++;} return IdUzkRoiMRf}" fullword ascii
    $s3  = "th.pow(Math.cos(296), 2) - 1)); while(true) { if(tyuEUAmQj[YZxmpuCbwKC] > lesyj[YZxmpuCbwKC].length-(26+925)/951) { break; } if " ascii
    $s4  = ") - 1));while(true){if (YZxmpuCbwKC >= (5278+674)/992){break;}tyuEUAmQj[YZxmpuCbwKC]=Math.round((Math.pow(Math.sin(296), 2) + Ma" ascii
    $s5  = "function rxdaBkiYURxsQVLpQ(lesyj){IdUzkRoiMRf= '';YZxmpuCbwKC=Math.round((Math.pow(Math.sin(766), 2) + Math.pow(Math.cos(766), 2" ascii
    $s6  = "function MCECJGMPCMDNslIFkzbxKcRdIskxJJUsuuoXcogfuLirZCTBOkHHtc(xodYPkTqNpYaC,sSxkpzjmBRwCzn){ return xFKoUsr[QWnLDvdn[QiOLc(xod" ascii
    $s7  = "function KghmdRx(MlwoXcWrlDBbYWGrpvCiWGwgyyAkuceRdnnk) {return !oiMiZcJORTc(uHkdsqKCoRGWsuo(MlwoXcWrlDBbYWGrpvCiWGwgyyAkuceRdnnk" ascii
    $s8  = "function MCECJGMPCMDNslIFkzbxKcRdIskxJJUsuuoXcogfuLirZCTBOkHHtc(xodYPkTqNpYaC,sSxkpzjmBRwCzn){ return xFKoUsr[QWnLDvdn[QiOLc(xod" ascii
    $s9  = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s10 = "function pqCQBIvBqzDo(WmncdCWXfmcXS) {return isFinite(WmncdCWXfmcXS);}" fullword ascii
    $s11 = "function C(QJwLHbrEtTxiAw,EPOqCmXyvVAPL,wCZAPXuWJet) {QJwLHbrEtTxiAw[EPOqCmXyvVAPL]=wCZAPXuWJet;}" fullword ascii
    $s12 = "function KghmdRx(MlwoXcWrlDBbYWGrpvCiWGwgyyAkuceRdnnk) {return !oiMiZcJORTc(uHkdsqKCoRGWsuo(MlwoXcWrlDBbYWGrpvCiWGwgyyAkuceRdnnk" ascii
    $s13 = "K);return nnabm;}" fullword ascii
    $s14 = "function uHkdsqKCoRGWsuo(HENUOsSDAPBxDkXVmvt) {return parseFloat(HENUOsSDAPBxDkXVmvt);}" fullword ascii
    $s15 = "function QiOLc(WRnLtXsrFDE,fMNygjZKvirBV,LTYJngDK){MUGh=dqKujKhHgovHDmQAh(WRnLtXsrFDE,fMNygjZKvirBV);nnabm=MUGh.toString(LTYJngD" ascii
    $s16 = "function QiOLc(WRnLtXsrFDE,fMNygjZKvirBV,LTYJngDK){MUGh=dqKujKhHgovHDmQAh(WRnLtXsrFDE,fMNygjZKvirBV);nnabm=MUGh.toString(LTYJngD" ascii
    $s17 = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s18 = "function oiMiZcJORTc(GYIZTGyvedpbYn) {return isNaN(GYIZTGyvedpbYn);}" fullword ascii
    $s19 = "function g(PNuxfamSEfpe,CqFaPISDuoFLJW){PNuxfamSEfpe.push(CqFaPISDuoFLJW);}" fullword ascii
    $s20 = "function dqKujKhHgovHDmQAh(jysxPtKsPT,UJnTuNXKKS) {return parseInt(jysxPtKsPT,UJnTuNXKKS);}" fullword ascii

  condition:
    uint16(0) == 0x5751 and
    8 of them
}