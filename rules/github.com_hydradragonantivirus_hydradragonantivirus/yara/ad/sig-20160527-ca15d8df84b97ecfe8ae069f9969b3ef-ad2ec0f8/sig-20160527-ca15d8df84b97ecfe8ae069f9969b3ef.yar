rule sig_20160527_ca15d8df84b97ecfe8ae069f9969b3ef {
  meta:
    description = "datamaliciousorder - file 20160527_ca15d8df84b97ecfe8ae069f9969b3ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c06f8106481e50a27438e8de040dcd90b4440eda6facc8e9039f1b13b22b58ee"

  strings:
    $s1  = "function LYHCnFmsh() {return WScript;}function XfquEUAuetOZ(){return TVkDOwsNh.ExpandEnvironmentStrings(CdnASpmr())}" fullword ascii
    $s2  = "function BeAulOyNIt(yhKLoTeYEcskO,ldiUwiAMfDPDZYDoA){return String.fromCharCode(yhKLoTeYEcskO,ldiUwiAMfDPDZYDoA);}" fullword ascii
    $s3  = "function MwxEZkisMnbStwDCrSgcfVO(JAZJN,MrIxGfjyRzCezi){return JAZJN.charAt(MrIxGfjyRzCezi);}" fullword ascii
    $s4  = "function CdnASpmr(){return ZxCcyOe(gQbhyCMkNF[8],[1,5,7],gQbhyCMkNF[9]);}" fullword ascii
    $s5  = "function xLISd(){return ZxCcyOe(gQbhyCMkNF[12],[0,3,6],gQbhyCMkNF[13]);}" fullword ascii
    $s6  = "ode(92)+gQbhyCMkNF[4],true);" fullword ascii
    $s7  = "function zyxjPcCTXF(WtOFtsKk,LiXYG) {var oNpSyZuIBefPY=[gQbhyCMkNF[15]];WtOFtsKk[oNpSyZuIBefPY[0]](LiXYG,0x1,0x0)}" fullword ascii
    $s8  = "var zVHjhbodmua = LFChGNuWbmwLtc.createtextfile(TVkDOwsNh.ExpandEnvironmentStrings(gQbhyCMkNF[2]+gQbhyCMkNF[3])+String.fromCharC" ascii
    $s9  = "Guc=0;LgzRUJEawlGuc<stTdtPlMCLa.length;LgzRUJEawlGuc++) {eKRqnuShdSjR+=pgOslkWk[stTdtPlMCLa[LgzRUJEawlGuc]];}return eKRqnuShdSjR" ascii
    $s10 = "lwwXqk == 64) ssklU += Yx(Lirqn);else if (kqCPrLVqBStEAYEOWgXl == 64) ssklU += BeAulOyNIt(Lirqn, xLgCFwUWD);else ssklU += WNQtqq" ascii
    $s11 = "function ZxCcyOe(uRWJbiPy,stTdtPlMCLa,rXlUvQGnj){pgOslkWk=uRWJbiPy.split(rXlUvQGnj);eKRqnuShdSjR = gQbhyCMkNF[14];for(LgzRUJEawl" ascii
    $s12 = "function ODxWeBfMJpG(aCdYufnlHafRsvwqYQVIt,GDlRAJSIXXhjHtGnAw){return aCdYufnlHafRsvwqYQVIt.indexOf(GDlRAJSIXXhjHtGnAw);}" fullword ascii
    $s13 = "function Yx(RQFoiynJb){return String.fromCharCode(RQFoiynJb);}" fullword ascii
    $s14 = "var LFChGNuWbmwLtc=function(){return new ActiveXObject(gQbhyCMkNF[0]);}();" fullword ascii
    $s15 = "var TVkDOwsNh=function(){return LYHCnFmsh().CreateObject(gQbhyCMkNF[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s16 = "function UDblRjFYHbPQ(lsGzRXYHulpxK) {var OtvEI = NUjdmIkiMQFzaVeMajGBL.join(gQbhyCMkNF[6]);var Lirqn, xLgCFwUWD, okKEDFxebrTFxn" ascii
    $s17 = "function kMwvGfr(){return ZxCcyOe(gQbhyCMkNF[10],[2,4,8,10],gQbhyCMkNF[11]);}" fullword ascii
    $s18 = "function ZxCcyOe(uRWJbiPy,stTdtPlMCLa,rXlUvQGnj){pgOslkWk=uRWJbiPy.split(rXlUvQGnj);eKRqnuShdSjR = gQbhyCMkNF[14];for(LgzRUJEawl" ascii
    $s19 = "function UDblRjFYHbPQ(lsGzRXYHulpxK) {var OtvEI = NUjdmIkiMQFzaVeMajGBL.join(gQbhyCMkNF[6]);var Lirqn, xLgCFwUWD, okKEDFxebrTFxn" ascii
    $s20 = "MTMf(Lirqn, xLgCFwUWD, okKEDFxebrTFxnTamPYiEeae);} while (rebfRlYHfuAJ < lsGzRXYHulpxK.length);return ssklU;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}