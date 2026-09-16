rule sig_20160523_95aec5e0dd8bfcd44c1b1b79bb7a39ba {
  meta:
    description = "datamaliciousorder - file 20160523_95aec5e0dd8bfcd44c1b1b79bb7a39ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5607f1eefe7616739528b4e6e3151781ec1d06b742fecab83275af04c3d92baf"

  strings:
    $s1  = "function XdSNozhazq(ksLPTNCG,AKebXhUMBBeX) {ksLPTNCG.Run(AKebXhUMBBeX, 0x1, 0x0);}" fullword ascii
    $s2  = "function oIgoxVrG(DRvfs) {var PRSbFDxq=isnHEwiOvw[13];for(var GeZwK=0;GeZwK<DRvfs;GeZwK++){rdejQ+=PRSbFDxq.charAt(Math.floor(Mat" ascii
    $s3  = "function oIgoxVrG(DRvfs) {var PRSbFDxq=isnHEwiOvw[13];for(var GeZwK=0;GeZwK<DRvfs;GeZwK++){rdejQ+=PRSbFDxq.charAt(Math.floor(Mat" ascii
    $s4  = "function ewXHcXLZ(tElEgBnxV) {tElEgBnxV.type=1;}" fullword ascii
    $s5  = "function BkaSPUo(zcIJ,YzslS) {zcIJ.write(YzslS);}" fullword ascii
    $s6  = "h.random()*PRSbFDxq.length));}return rdejQ;}" fullword ascii
    $s7  = "function cIJskgL(iYsZg) {iYsZg.close();}" fullword ascii
    $s8  = "function SKmg(jkdezO,bSZogcw){dQNZ = isnHEwiOvw[10].split(isnHEwiOvw[11]);bSZogcw.open(dQNZ[0]+dQNZ[2]+dQNZ[3], jkdezO, false);b" ascii
    $s9  = "function SqsmsubLL(XNuiOy) {var TuoHlHnncG=[];XNuiOy.position=TuoHlHnncG.length*(1373895-568);}" fullword ascii
    $s10 = "function PmchlPb() {var CRwq=100000;var XmRmQB = 100;return psCBnSR()*(CRwq-XmRmQB)+XmRmQB;}" fullword ascii
    $s11 = "function KKxvo(mqoqXCPA,jGdeO,AKOeJOPXfT){Virr(mqoqXCPA);ewXHcXLZ(mqoqXCPA);BkaSPUo(mqoqXCPA,jGdeO);SqsmsubLL(mqoqXCPA);dOwC(mqo" ascii
    $s12 = "function psCBnSR(){return Math.random();}" fullword ascii
    $s13 = "function dOwC(DjZhdVP,HxYxMcP) {DjZhdVP.saveToFile(HxYxMcP, 2);}" fullword ascii
    $s14 = "function RlamUt(xJpNcY){return xJpNcY.ExpandEnvironmentStrings(isnHEwiOvw[9])}" fullword ascii
    $s15 = "function dzZRV(xJpNcY){return new ActiveXObject(xJpNcY);}" fullword ascii
    $s16 = "function Virr(GxTpBh) {GxTpBh.open();}" fullword ascii
    $s17 = "function SKmg(jkdezO,bSZogcw){dQNZ = isnHEwiOvw[10].split(isnHEwiOvw[11]);bSZogcw.open(dQNZ[0]+dQNZ[2]+dQNZ[3], jkdezO, false);b" ascii
    $s18 = "if(gXex>XyCBN.length) break;" fullword ascii
    $s19 = "function KKxvo(mqoqXCPA,jGdeO,AKOeJOPXfT){Virr(mqoqXCPA);ewXHcXLZ(mqoqXCPA);BkaSPUo(mqoqXCPA,jGdeO);SqsmsubLL(mqoqXCPA);dOwC(mqo" ascii
    $s20 = "s.length;CAYfiZdW++) {wwPuqTp+=KUWRm[WUUKVs[CAYfiZdW]];}return wwPuqTp.substring(3,wwPuqTp.length);}" fullword ascii

  condition:
    uint16(0) == 0x1027 and
    8 of them
}