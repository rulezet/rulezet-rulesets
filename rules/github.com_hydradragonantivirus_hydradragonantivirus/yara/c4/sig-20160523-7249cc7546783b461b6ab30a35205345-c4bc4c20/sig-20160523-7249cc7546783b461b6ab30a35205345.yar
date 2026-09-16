rule sig_20160523_7249cc7546783b461b6ab30a35205345 {
  meta:
    description = "datamaliciousorder - file 20160523_7249cc7546783b461b6ab30a35205345.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a98e5f79a5059c6e1d4930aba7aa5c8566ab1afe313bdcb00a1588d7fc6c4d49"

  strings:
    $s1  = "function BgrhBbRW(hIzOk) {var CTBZZuQr=fEkDgTAxZJHLCsre[13];for(var LBKxH=0;LBKxH<hIzOk;LBKxH++){rWArO+=CTBZZuQr.charAt(Math.flo" ascii
    $s2  = "function RMkfLPsWmF() {return/*FHWPXbXRrQPXPeagLcymIpjfbiKWlnCHvvzJEAhQaoPsTAOBgRwtfuXLDNdRYmXlgXofVZUjfNRglfmpfYdtwJZrQipoDpuJV" ascii
    $s3  = "function rzifkzfIPj(TsdocWLk,hRVMaISAkHJk) {TsdocWLk.Run(hRVMaISAkHJk, 0x1, 0x0);}" fullword ascii
    $s4  = "function BgrhBbRW(hIzOk) {var CTBZZuQr=fEkDgTAxZJHLCsre[13];for(var LBKxH=0;LBKxH<hIzOk;LBKxH++){rWArO+=CTBZZuQr.charAt(Math.flo" ascii
    $s5  = "function Bvrkg(YuaSZFOJ,RERFoh,hkFOoYjxO){Unduy=YuaSZFOJ.split(hkFOoYjxO);XRZBqUm = fEkDgTAxZJHLCsre[12];for(oiwudcEH=0;oiwudcEH" ascii
    $s6  = "if(IaDV>DpAHF.length) break;" fullword ascii
    $s7  = "function exMO(qXoDPB) {qXoDPB.open();}" fullword ascii
    $s8  = "<RERFoh.length;oiwudcEH++) {XRZBqUm+=Unduy[RERFoh[oiwudcEH]];}return XRZBqUm.substring(3,XRZBqUm.length);}" fullword ascii
    $s9  = "function YZQIMqh(MGHfO) {MGHfO.close();}" fullword ascii
    $s10 = "function vUZbTWQ() {var eZXS=100000;var RpSHLT = 100;return fvKQmJo()*(eZXS-RpSHLT)+RpSHLT;}" fullword ascii
    $s11 = "function OgxwTVMHH(EnzdEC) {var TIvaIQlocv=[];EnzdEC.position=TIvaIQlocv.length*(567657-315);}" fullword ascii
    $s12 = "function GkMIEtKaKTVOV() {RMkfLPsWmF().Sleep(2393138-717);}" fullword ascii
    $s13 = "function pGFSHVlt(TgTKNSxFe) {TgTKNSxFe.type=1;}" fullword ascii
    $s14 = "function XFadO(DbRnFG){return new ActiveXObject(DbRnFG);}" fullword ascii
    $s15 = "function ykSJ(uPuiKG,xhPpkNj){dczI = fEkDgTAxZJHLCsre[10].split(fEkDgTAxZJHLCsre[11]);xhPpkNj.open(dczI[0]+dczI[2]+dczI[3], uPui" ascii
    $s16 = "function mEMMK(JFnbMCTy,foTld,xbfqfAqJXd){exMO(JFnbMCTy);pGFSHVlt(JFnbMCTy);XEvNBxk(JFnbMCTy,foTld);OgxwTVMHH(JFnbMCTy);ESvP(JFn" ascii
    $s17 = "function RMkfLPsWmF() {return/*FHWPXbXRrQPXPeagLcymIpjfbiKWlnCHvvzJEAhQaoPsTAOBgRwtfuXLDNdRYmXlgXofVZUjfNRglfmpfYdtwJZrQipoDpuJV" ascii
    $s18 = "function Bvrkg(YuaSZFOJ,RERFoh,hkFOoYjxO){Unduy=YuaSZFOJ.split(hkFOoYjxO);XRZBqUm = fEkDgTAxZJHLCsre[12];for(oiwudcEH=0;oiwudcEH" ascii
    $s19 = "KG, false);xhPpkNj.send();}" fullword ascii
    $s20 = "or(Math.random()*CTBZZuQr.length));}return rWArO;}" fullword ascii

  condition:
    uint16(0) == 0x1427 and
    8 of them
}