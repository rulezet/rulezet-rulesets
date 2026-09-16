rule sig_20160527_b5b969b9298bf7617bf6895af78c20e7 {
  meta:
    description = "datamaliciousorder - file 20160527_b5b969b9298bf7617bf6895af78c20e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd9319e0b1938d6da89b19ec23ebf9212b269c09c3a9897ffeeac3d5ccf4969c"

  strings:
    $s1  = "function MMGQXCUQnf() {return WScript;}function haFdVay(){return eQNrKaiCoj.ExpandEnvironmentStrings(tNFzgCMH())}" fullword ascii
    $s2  = "function tefzm(bciurMSJyrCDnqXBVthxVtoY,FBPQYyvwVkx){return bciurMSJyrCDnqXBVthxVtoY.charAt(FBPQYyvwVkx);}" fullword ascii
    $s3  = "qOL += prMpbyOryQWDHHJDvRYVTd(TPMAVHKVETW, MwnfgIzdTMokNGOUsfakhRyR, pnoZCMGPji);} while (bliQhprjuQqdj < QsVVJiZHUuYbx.length);" ascii
    $s4  = "function NinJvemImodUzNvlby(RwXeLmahSYoAvp,nWSRjtwoPqPZRiBpllf){return RwXeLmahSYoAvp.indexOf(nWSRjtwoPqPZRiBpllf);}" fullword ascii
    $s5  = "zplyl=0;ozplyl<mRMGNWVa.length;ozplyl++) {hsGadFoaq+=MUQyTFxVZZGujc[mRMGNWVa[ozplyl]];}return hsGadFoaq.substring(3,hsGadFoaq.le" ascii
    $s6  = "return PEUNjPKAqOL;}" fullword ascii
    $s7  = "function V(ogkjJDyjbZTwSsQsh){return String.fromCharCode(ogkjJDyjbZTwSsQsh);}" fullword ascii
    $s8  = "function CYbpuOdzox(tBzqobeA,mRMGNWVa,JrPNPmwaOZk){MUQyTFxVZZGujc=tBzqobeA.split(JrPNPmwaOZk);hsGadFoaq = VjwpMfFgCAAr[14];for(o" ascii
    $s9  = "var WkYMJBZSv = DOOxpOwmRgDmeq.createtextfile(eQNrKaiCoj.ExpandEnvironmentStrings(VjwpMfFgCAAr[2]+VjwpMfFgCAAr[3])+String.fromCh" ascii
    $s10 = "function wzfRSmu(QsVVJiZHUuYbx) {var lGYpJqDVeE = VGqAdxH.join(VjwpMfFgCAAr[6]);var TPMAVHKVETW, MwnfgIzdTMokNGOUsfakhRyR, pnoZC" ascii
    $s11 = "TW);else if (qbmYHciBqvOaxOwZDPJPj == 64) PEUNjPKAqOL += QJeAxzRICcaSwpbMjt(TPMAVHKVETW, MwnfgIzdTMokNGOUsfakhRyR);else PEUNjPKA" ascii
    $s12 = "function UsvgKH(){return CYbpuOdzox(VjwpMfFgCAAr[10],[2,4,8,10],VjwpMfFgCAAr[11]);}" fullword ascii
    $s13 = "function CYbpuOdzox(tBzqobeA,mRMGNWVa,JrPNPmwaOZk){MUQyTFxVZZGujc=tBzqobeA.split(JrPNPmwaOZk);hsGadFoaq = VjwpMfFgCAAr[14];for(o" ascii
    $s14 = "function QJeAxzRICcaSwpbMjt(AczDoZtHtUeDFBxEsC,IKCuQT){return String.fromCharCode(AczDoZtHtUeDFBxEsC,IKCuQT);}" fullword ascii
    $s15 = "arCode(92)+VjwpMfFgCAAr[4],true);" fullword ascii
    $s16 = "function vmWdJSqiWYQhUj(){return CYbpuOdzox(VjwpMfFgCAAr[12],[0,3,6],VjwpMfFgCAAr[13]);}" fullword ascii
    $s17 = "function prMpbyOryQWDHHJDvRYVTd(CaoxnfBdNMTsT,HMfrfXbdUR,mjluUkuDtCEC){return String.fromCharCode(CaoxnfBdNMTsT,HMfrfXbdUR,mjluU" ascii
    $s18 = "function tNFzgCMH(){return CYbpuOdzox(VjwpMfFgCAAr[8],[1,5,7],VjwpMfFgCAAr[9]);}" fullword ascii
    $s19 = "var DOOxpOwmRgDmeq=function(){return new ActiveXObject(VjwpMfFgCAAr[0]);}();" fullword ascii
    $s20 = "function wzfRSmu(QsVVJiZHUuYbx) {var lGYpJqDVeE = VGqAdxH.join(VjwpMfFgCAAr[6]);var TPMAVHKVETW, MwnfgIzdTMokNGOUsfakhRyR, pnoZC" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}