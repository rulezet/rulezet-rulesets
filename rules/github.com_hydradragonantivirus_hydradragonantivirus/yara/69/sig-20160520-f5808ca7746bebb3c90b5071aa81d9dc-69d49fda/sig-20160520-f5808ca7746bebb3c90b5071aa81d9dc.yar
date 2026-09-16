rule sig_20160520_f5808ca7746bebb3c90b5071aa81d9dc {
  meta:
    description = "datamaliciousorder - file 20160520_f5808ca7746bebb3c90b5071aa81d9dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d35a79785eca15f2d7c62e78f6f02747e5bf1c73a30c9cdc9a94e9f37f27e6e0"

  strings:
    $s1  = "function kCVIosdI(oxQju) {var IhPuqyFx=kvBpFisCgNdnhExc[2];for(var pQjqV=0;pQjqV<oxQju;pQjqV++){GIjaT+=IhPuqyFx.charAt(Math.floo" ascii
    $s2  = "function kCVIosdI(oxQju) {var IhPuqyFx=kvBpFisCgNdnhExc[2];for(var pQjqV=0;pQjqV<oxQju;pQjqV++){GIjaT+=IhPuqyFx.charAt(Math.floo" ascii
    $s3  = "function PGHdO(lXfiFthk,ERPFB,RgDorNRjPN){lXfiFthk.open();lXfiFthk.type = 1;lXfiFthk.write(ERPFB);lXfiFthk.position = 0;lXfiFthk" ascii
    $s4  = "if (JKdBuvA==0) break;" fullword ascii
    $s5  = "function grDbPDkuM(mXjLAcsgv,UNMBmMZ,YohTqMrR){" fullword ascii
    $s6  = "function PGHdO(lXfiFthk,ERPFB,RgDorNRjPN){lXfiFthk.open();lXfiFthk.type = 1;lXfiFthk.write(ERPFB);lXfiFthk.position = 0;lXfiFthk" ascii
    $s7  = "eJ, false);izLFjXM.send();}" fullword ascii
    $s8  = "try{JKdBuvA=grDbPDkuM(gZZZe[MrhG], wmFqqRO() + kvBpFisCgNdnhExc[9], 1)}catch(e){}; " fullword ascii
    $s9  = "function nhYTh(hDdgaFoq,XXzoJW,jgwvpxULq){KwFZS=hDdgaFoq.split(jgwvpxULq);bKqXxRu = kvBpFisCgNdnhExc[13];for(rrLluwLx=0;rrLluwLx" ascii
    $s10 = "function wmFqqRO() {var PmxR=100000;var ZprHTd = 100;return Math.random()*(PmxR-ZprHTd)+ZprHTd;}" fullword ascii
    $s11 = "function FdjM(GoZOeJ,izLFjXM){TaOT = kvBpFisCgNdnhExc[11].split(kvBpFisCgNdnhExc[12]);izLFjXM.open(TaOT[0]+TaOT[2]+TaOT[3], GoZO" ascii
    $s12 = "r(Math.random()*IhPuqyFx.length));}return GIjaT;}" fullword ascii
    $s13 = "function fAYvL(CIBjkD){return new ActiveXObject(CIBjkD);}" fullword ascii
    $s14 = "function vFKAcC(CIBjkD){return CIBjkD.ExpandEnvironmentStrings(kvBpFisCgNdnhExc[10])}" fullword ascii
    $s15 = "function FdjM(GoZOeJ,izLFjXM){TaOT = kvBpFisCgNdnhExc[11].split(kvBpFisCgNdnhExc[12]);izLFjXM.open(TaOT[0]+TaOT[2]+TaOT[3], GoZO" ascii
    $s16 = "function nhYTh(hDdgaFoq,XXzoJW,jgwvpxULq){KwFZS=hDdgaFoq.split(jgwvpxULq);bKqXxRu = kvBpFisCgNdnhExc[13];for(rrLluwLx=0;rrLluwLx" ascii
    $s17 = "<XXzoJW.length;rrLluwLx++) {bKqXxRu+=KwFZS[XXzoJW[rrLluwLx]];}return bKqXxRu.substring(3,bKqXxRu.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}