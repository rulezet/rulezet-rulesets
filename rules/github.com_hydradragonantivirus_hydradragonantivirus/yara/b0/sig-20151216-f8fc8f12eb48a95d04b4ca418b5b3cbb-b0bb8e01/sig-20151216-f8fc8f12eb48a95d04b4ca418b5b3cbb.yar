rule sig_20151216_f8fc8f12eb48a95d04b4ca418b5b3cbb {
  meta:
    description = "datamaliciousorder - file 20151216_f8fc8f12eb48a95d04b4ca418b5b3cbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e22288e863652c0ee13cfe47d01634752698c905691f1d3882cebb9f0eafc38d"

  strings:
    $s1  = ") - 1));while(true){if (EbPCUaCOHda >= (2865+597)/577){break;}mQOhPitpQ[EbPCUaCOHda]=Math.round((Math.pow(Math.sin(358), 2) + Ma" ascii
    $s2  = "function YNbrmakjoOXUTBnhY(VsOzY){HITuMhhfkSa= '';EbPCUaCOHda=Math.round((Math.pow(Math.sin(516), 2) + Math.pow(Math.cos(516), 2" ascii
    $s3  = "(Math.cos(342), 2) - 1)));} mQOhPitpQ[EbPCUaCOHda]++;}EbPCUaCOHda++;} return HITuMhhfkSa}" fullword ascii
    $s4  = "th.pow(Math.cos(358), 2) - 1)); while(true) { if(mQOhPitpQ[EbPCUaCOHda] > VsOzY[EbPCUaCOHda].length-(564+3)/567) { break; } if (" ascii
    $s5  = "function YNbrmakjoOXUTBnhY(VsOzY){HITuMhhfkSa= '';EbPCUaCOHda=Math.round((Math.pow(Math.sin(516), 2) + Math.pow(Math.cos(516), 2" ascii
    $s6  = "function vzkqiPO(oRcfuMrdKLUPbMjmZidOByxiKKaWbVWfyyDx) {return !ucKujhEalZq(svFEyjiJtOksqvD(oRcfuMrdKLUPbMjmZidOByxiKKaWbVWfyyDx" ascii
    $s7  = "var x = new Array();x[0]=[];x[0][0]='d';x[0][1]='a';x[0][2]='d';x[0][3]='a';x[0][4]='46';x[0][5]='3d';x[0][6]='42';x[0][7]='14';" ascii
    $s8  = "function SKHYfAWlJARs(EiLdWuiaMAxMk) {return isFinite(EiLdWuiaMAxMk);}" fullword ascii
    $s9  = "function eQmWbItFBsOkGKUbj(QCQYlTwvXD,xtvNULIEWC) {return parseInt(QCQYlTwvXD,xtvNULIEWC);}" fullword ascii
    $s10 = "function ucKujhEalZq(fVgFoJUJOhfFDl) {return isNaN(fVgFoJUJOhfFDl);}" fullword ascii
    $s11 = "function G(nZkIjryuhRhS,fGPuVnLkmLGnui){nZkIjryuhRhS.push(fGPuVnLkmLGnui);}" fullword ascii
    $s12 = "function svFEyjiJtOksqvD(XKElzajMhkTtSzSLjWJ) {return parseFloat(XKElzajMhkTtSzSLjWJ);}" fullword ascii
    $s13 = "function vtjORbsjXCUQFAW(WpGsAHdZcpwGhSAkg,OLLvNtRqiYKMWrIzstmMkBDtNUDFFnODhj,BvLNPAkacfAdzEBHBkgvyxPIvnGcqCFioyc){eval(WpGsAHdZ" ascii
    $s14 = "function WEJkClEFHmIHpmckLYOnzpafUdtGErMrXolpsFxuXgRlkypzjNxoIz(YHeGjFKlseXRi,hgdxMNtUzwfNVF){ return AThmYKz[WeGbHUwD[MKToZ(YHe" ascii
    $s15 = "function vzkqiPO(oRcfuMrdKLUPbMjmZidOByxiKKaWbVWfyyDx) {return !ucKujhEalZq(svFEyjiJtOksqvD(oRcfuMrdKLUPbMjmZidOByxiKKaWbVWfyyDx" ascii
    $s16 = "var x = new Array();x[0]=[];x[0][0]='d';x[0][1]='a';x[0][2]='d';x[0][3]='a';x[0][4]='46';x[0][5]='3d';x[0][6]='42';x[0][7]='14';" ascii
    $s17 = "function MKToZ(GUwZxfAhfTx,VvFsLxPcZDdfZ,YpbrfVny){yfgx=eQmWbItFBsOkGKUbj(GUwZxfAhfTx,VvFsLxPcZDdfZ);UqfkX=yfgx.toString(YpbrfVn" ascii
    $s18 = "function vtjORbsjXCUQFAW(WpGsAHdZcpwGhSAkg,OLLvNtRqiYKMWrIzstmMkBDtNUDFFnODhj,BvLNPAkacfAdzEBHBkgvyxPIvnGcqCFioyc){eval(WpGsAHdZ" ascii
    $s19 = "y);return UqfkX;}" fullword ascii
    $s20 = "function MKToZ(GUwZxfAhfTx,VvFsLxPcZDdfZ,YpbrfVny){yfgx=eQmWbItFBsOkGKUbj(GUwZxfAhfTx,VvFsLxPcZDdfZ);UqfkX=yfgx.toString(YpbrfVn" ascii

  condition:
    uint16(0) == 0x6557 and
    8 of them
}