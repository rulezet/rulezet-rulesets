rule sig_20151217_3820b4624a00f0e8aece0f26bd2c6784 {
  meta:
    description = "datamaliciousorder - file 20151217_3820b4624a00f0e8aece0f26bd2c6784.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c83a3e6f8d8ecf9f810deebb6fc91a4305c6c08dc4f3690ea6fc851cfcd72997"

  strings:
    $s1  = "ow(Math.cos(766), 2) - 1)));} RFpZMxDAV[nYYOKnSKMNc]++;}nYYOKnSKMNc++;} return RjYMxDqIsva}" fullword ascii
    $s2  = "h.pow(Math.cos(208), 2) - 1)); while(true) { if(RFpZMxDAV[nYYOKnSKMNc] > majeZ[nYYOKnSKMNc].length-(-249+275)/26) { break; } if " ascii
    $s3  = "function WVTyXueIyXHdjzuKg(majeZ){RjYMxDqIsva= '';nYYOKnSKMNc=Math.round((Math.pow(Math.sin(526), 2) + Math.pow(Math.cos(526), 2" ascii
    $s4  = ") - 1));while(true){if (nYYOKnSKMNc >= (5295+69)/894){break;}RFpZMxDAV[nYYOKnSKMNc]=Math.round((Math.pow(Math.sin(208), 2) + Mat" ascii
    $s5  = "function WVTyXueIyXHdjzuKg(majeZ){RjYMxDqIsva= '';nYYOKnSKMNc=Math.round((Math.pow(Math.sin(526), 2) + Math.pow(Math.cos(526), 2" ascii
    $s6  = "function u(vUCecpcfhSpYoq,yOWDcrfAzyUlJ,JuGIBGsbrKv) {vUCecpcfhSpYoq[yOWDcrfAzyUlJ]=JuGIBGsbrKv;}" fullword ascii
    $s7  = "function aXhJftk(TnoLiIHViJVTJeaXZwfcYbLQUubpJKRhpXcy) {return !UrJJKZYrsgv(TnuBXKYLtOwNMcw(TnoLiIHViJVTJeaXZwfcYbLQUubpJKRhpXcy" ascii
    $s8  = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s9  = "function ROfLHJmmwNLMpyp(dONCgzBtREfWoBSHE,ZjEhUyenuYiwznVtEweMXYdrnyHAqDPyku,cFQqFFeRJwxnvbsmjPCFiFlinxGgulQCVKL){eval(dONCgzBt" ascii
    $s10 = "function yLkRe(IiOHSTYvFjb,dijcIBrlHqMyh,wjZjQctq){GWwE=TDGmsnQBFoOyUMJIy(IiOHSTYvFjb,dijcIBrlHqMyh);MjOEk=GWwE.toString(wjZjQct" ascii
    $s11 = "function qVFWSXDgriwC(StoSNYlyxKPyy) {return isFinite(StoSNYlyxKPyy);}" fullword ascii
    $s12 = "function TnuBXKYLtOwNMcw(modjSynSXxooiAZmfcS) {return parseFloat(modjSynSXxooiAZmfcS);}" fullword ascii
    $s13 = "function bupMOlYRxuXtHuPYJDluYoEjAyEuaEMNFmCfQdXlcKyKRmuHefHTWD(SeOvqeqodZUDw,AbhJaUinKSiCCh){ return pzcHZue[DuMLRjmP[yLkRe(SeO" ascii
    $s14 = "function bupMOlYRxuXtHuPYJDluYoEjAyEuaEMNFmCfQdXlcKyKRmuHefHTWD(SeOvqeqodZUDw,AbhJaUinKSiCCh){ return pzcHZue[DuMLRjmP[yLkRe(SeO" ascii
    $s15 = "function M(TFuxjDHLfpGW,HrjiRqGkkbDUjn){TFuxjDHLfpGW.push(HrjiRqGkkbDUjn);}" fullword ascii
    $s16 = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s17 = "function TDGmsnQBFoOyUMJIy(CjiqKfnOTe,hzlHSXgcXN) {return parseInt(CjiqKfnOTe,hzlHSXgcXN);}" fullword ascii
    $s18 = "function aXhJftk(TnoLiIHViJVTJeaXZwfcYbLQUubpJKRhpXcy) {return !UrJJKZYrsgv(TnuBXKYLtOwNMcw(TnoLiIHViJVTJeaXZwfcYbLQUubpJKRhpXcy" ascii
    $s19 = "function yLkRe(IiOHSTYvFjb,dijcIBrlHqMyh,wjZjQctq){GWwE=TDGmsnQBFoOyUMJIy(IiOHSTYvFjb,dijcIBrlHqMyh);MjOEk=GWwE.toString(wjZjQct" ascii
    $s20 = "q);return MjOEk;}" fullword ascii

  condition:
    uint16(0) == 0x7544 and
    8 of them
}