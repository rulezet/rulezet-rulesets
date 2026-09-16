rule sig_20160523_c7120f8dfe23df037f0e04f084faa966 {
  meta:
    description = "datamaliciousorder - file 20160523_c7120f8dfe23df037f0e04f084faa966.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f79c84319d5498d622739a077d1e01ad51329ec4a582bdc1711c48f10cf7a01b"

  strings:
    $s1  = "function ElZRqNNb(DSVxy) {var LqcEcppb=Khttk[13];for(var eLjtC=0;eLjtC<DSVxy;eLjtC++){UhMHK+=LqcEcppb.charAt(Math.floor(Math.ran" ascii
    $s2  = "function XVTzqUaNIo(IbWHCGFd,UuIhuJCZprnj) {IbWHCGFd.Run(UuIhuJCZprnj, 0x1, 0x0);}" fullword ascii
    $s3  = "function ElZRqNNb(DSVxy) {var LqcEcppb=Khttk[13];for(var eLjtC=0;eLjtC<DSVxy;eLjtC++){UhMHK+=LqcEcppb.charAt(Math.floor(Math.ran" ascii
    $s4  = "function kXgt(jQiEtN,AQrzzzj){mYFA = Khttk[10].split(Khttk[11]);AQrzzzj.open(mYFA[0]+mYFA[2]+mYFA[3], jQiEtN, false);AQrzzzj.sen" ascii
    $s5  = "function KIlWZ(WXLywidF,meSsYv,vkKuFfbLL){tcCQl=WXLywidF.split(vkKuFfbLL);LzmxxUQ = Khttk[12];for(CcGIysRN=0;CcGIysRN<meSsYv.len" ascii
    $s6  = "function HCaqRuKN(jcEhIftPL) {jcEhIftPL.type=1;}" fullword ascii
    $s7  = "function RpSUmy(QwGAPw){return QwGAPw.ExpandEnvironmentStrings(Khttk[9])}" fullword ascii
    $s8  = "function kXgt(jQiEtN,AQrzzzj){mYFA = Khttk[10].split(Khttk[11]);AQrzzzj.open(mYFA[0]+mYFA[2]+mYFA[3], jQiEtN, false);AQrzzzj.sen" ascii
    $s9  = "function JqDrsgP(Zlar,HTIAO) {Zlar.write(HTIAO);}" fullword ascii
    $s10 = "function zErx(TqgwqW) {TqgwqW.open();}" fullword ascii
    $s11 = "function KIlWZ(WXLywidF,meSsYv,vkKuFfbLL){tcCQl=WXLywidF.split(vkKuFfbLL);LzmxxUQ = Khttk[12];for(CcGIysRN=0;CcGIysRN<meSsYv.len" ascii
    $s12 = "dom()*LqcEcppb.length));}return UhMHK;}" fullword ascii
    $s13 = "function jJFAqji() {var grTt=100000;var OKPzot = 100;return WBavuPA()*(grTt-OKPzot)+OKPzot;}" fullword ascii
    $s14 = "function xNSJMjN(cdkbt) {cdkbt.close();}" fullword ascii
    $s15 = "function WBavuPA(){return Math.random();}" fullword ascii
    $s16 = "gth;CcGIysRN++) {LzmxxUQ+=tcCQl[meSsYv[CcGIysRN]];}return LzmxxUQ.substring(3,LzmxxUQ.length);}" fullword ascii
    $s17 = "function HQHMf(QwGAPw){return new ActiveXObject(QwGAPw);}" fullword ascii
    $s18 = "function vsjqwOJOa(hSfMjc) {var PMfgOEHuBt=[];hSfMjc.position=PMfgOEHuBt.length*(381528-185);}" fullword ascii
    $s19 = "function aLcK(VxOIDvJ,RLXnrEW) {VxOIDvJ.saveToFile(RLXnrEW, 2);}" fullword ascii
    $s20 = "if(hktR>yWLZD.length) break;" fullword ascii

  condition:
    uint16(0) == 0x1a27 and
    8 of them
}