rule sig_20160520_0891558df68cc9560408c4837b3214e7 {
  meta:
    description = "datamaliciousorder - file 20160520_0891558df68cc9560408c4837b3214e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e3e2215d8f5724592e2beebb833607964e5c0a77de31c6a2a14530c381415ee"

  strings:
    $s1  = "function nNuXELGA(PRCer) {var ksAkwNiR=CNIEZOcgrOoiavCclgMYFOS[2];for(var EZTlp=0;EZTlp<PRCer;EZTlp++){OYRGq+=ksAkwNiR.charAt(Ma" ascii
    $s2  = "function nNuXELGA(PRCer) {var ksAkwNiR=CNIEZOcgrOoiavCclgMYFOS[2];for(var EZTlp=0;EZTlp<PRCer;EZTlp++){OYRGq+=ksAkwNiR.charAt(Ma" ascii
    $s3  = "function YOkmDpw() {var ZyRy=100000;var CbQtfd = 100;return Math.random()*(ZyRy-CbQtfd)+CbQtfd;}" fullword ascii
    $s4  = "+dXAO[3], fCzmYZ, false);FjCwQpY.send();}" fullword ascii
    $s5  = "function tsfZ(fCzmYZ,FjCwQpY){dXAO = CNIEZOcgrOoiavCclgMYFOS[11].split(CNIEZOcgrOoiavCclgMYFOS[12]);FjCwQpY.open(dXAO[0]+dXAO[2]" ascii
    $s6  = "th.floor(Math.random()*ksAkwNiR.length));}return OYRGq;}" fullword ascii
    $s7  = "function RFUgL(iDIlHH){return new ActiveXObject(iDIlHH);}" fullword ascii
    $s8  = "function bdpZy(BgDUloDt,tFWBK,ygwvKhJlGx){BgDUloDt.open();BgDUloDt.type = 1;BgDUloDt.write(tFWBK);BgDUloDt.position = 0;BgDUloDt" ascii
    $s9  = "function YQgtUy(iDIlHH){return iDIlHH.ExpandEnvironmentStrings(CNIEZOcgrOoiavCclgMYFOS[10])}" fullword ascii
    $s10 = "function tsfZ(fCzmYZ,FjCwQpY){dXAO = CNIEZOcgrOoiavCclgMYFOS[11].split(CNIEZOcgrOoiavCclgMYFOS[12]);FjCwQpY.open(dXAO[0]+dXAO[2]" ascii
    $s11 = "function bdpZy(BgDUloDt,tFWBK,ygwvKhJlGx){BgDUloDt.open();BgDUloDt.type = 1;BgDUloDt.write(tFWBK);BgDUloDt.position = 0;BgDUloDt" ascii
    $s12 = "try{mdcdEgRlK(NQohD[FsWa], YOkmDpw() + CNIEZOcgrOoiavCclgMYFOS[9], 1)}catch(e){}; " fullword ascii
    $s13 = "function mdcdEgRlK(oHaxAbhhn,gTHAzTo,LmvVSYiU){" fullword ascii
    $s14 = "function JFALU(WGHYvvFu,ievgNt,wHpzBVthZ){tndMq=WGHYvvFu.split(wHpzBVthZ);welrFMr = CNIEZOcgrOoiavCclgMYFOS[13];for(ueDKcaxa=0;u" ascii
    $s15 = "eDKcaxa<ievgNt.length;ueDKcaxa++) {welrFMr+=tndMq[ievgNt[ueDKcaxa]];}return welrFMr.substring(3,welrFMr.length);}" fullword ascii
    $s16 = "function JFALU(WGHYvvFu,ievgNt,wHpzBVthZ){tndMq=WGHYvvFu.split(wHpzBVthZ);welrFMr = CNIEZOcgrOoiavCclgMYFOS[13];for(ueDKcaxa=0;u" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}