rule sig_20160523_6bcba3ba7d8c6b3107a250d90edfd2b1 {
  meta:
    description = "datamaliciousorder - file 20160523_6bcba3ba7d8c6b3107a250d90edfd2b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44aed90715f26243877a3a291c6219a4ac09dba017aee3329bfc1f54468a9793"

  strings:
    $s1  = "function kUgMOoZCcQ(PaCfiNyY,EAvFerwBCEUj) {PaCfiNyY.Run(EAvFerwBCEUj, 0x1, 0x0);}" fullword ascii
    $s2  = "function LifVZsCKJS() {return/*wEskeqMaITCHYyhzoWemQPzVJWEAnxbmtnnkFqXxUSGwVxbunKijWJXNkBzRxjqhPvbIutklYMBPDPxirjdYSiyabNIGnEKpN" ascii
    $s3  = "function LjSpQFlO(otDvK) {var DzqhbVaZ=bRgVsELdYrx[13];for(var vcQLu=0;vcQLu<otDvK;vcQLu++){SsDyR+=DzqhbVaZ.charAt(Math.floor(Ma" ascii
    $s4  = "function LjSpQFlO(otDvK) {var DzqhbVaZ=bRgVsELdYrx[13];for(var vcQLu=0;vcQLu<otDvK;vcQLu++){SsDyR+=DzqhbVaZ.charAt(Math.floor(Ma" ascii
    $s5  = "th.random()*DzqhbVaZ.length));}return SsDyR;}" fullword ascii
    $s6  = "if(nqZm>jXcfM.length) break;" fullword ascii
    $s7  = "function SjVJvDnR(vAMViJiLs) {vAMViJiLs.type=1;}" fullword ascii
    $s8  = "function oyzyFWC(){return Math.random();}" fullword ascii
    $s9  = "function sExuWbFNP(WhlQbr) {var dhmWmNGkWR=[];WhlQbr.position=dhmWmNGkWR.length*(9097953-175);}" fullword ascii
    $s10 = "function LifVZsCKJS() {return/*wEskeqMaITCHYyhzoWemQPzVJWEAnxbmtnnkFqXxUSGwVxbunKijWJXNkBzRxjqhPvbIutklYMBPDPxirjdYSiyabNIGnEKpN" ascii
    $s11 = "function VyAXHbhImuUUE() {LifVZsCKJS().Sleep(2492852-443);}" fullword ascii
    $s12 = "function AOagVKM(yhEoz) {yhEoz.close();}" fullword ascii
    $s13 = "sPAK(ZyHoFzZIK,kahyx);" fullword ascii
    $s14 = "function vpzmjNo() {var ZpVL=100000;var cXxmLM = 100;return oyzyFWC()*(ZpVL-cXxmLM)+cXxmLM;}" fullword ascii
    $s15 = "function xjRWfG(SANBZW){return SANBZW.ExpandEnvironmentStrings(bRgVsELdYrx[9])}" fullword ascii
    $s16 = "function sPAK(Bazsex,pIymiNd){SFCt = bRgVsELdYrx[10].split(bRgVsELdYrx[11]);pIymiNd.open(SFCt[0]+SFCt[2]+SFCt[3], Bazsex, false)" ascii
    $s17 = "function leMQG(JSFkvFNR,aYhxHk,tkztNgQZy){aWAZK=JSFkvFNR.split(tkztNgQZy);fMyxqIn = bRgVsELdYrx[12];for(zfiRrKsM=0;zfiRrKsM<aYhx" ascii
    $s18 = "function leMQG(JSFkvFNR,aYhxHk,tkztNgQZy){aWAZK=JSFkvFNR.split(tkztNgQZy);fMyxqIn = bRgVsELdYrx[12];for(zfiRrKsM=0;zfiRrKsM<aYhx" ascii
    $s19 = "function QlUdU(olKvVoEm,ROaVO,PrgQivGoMD){lkNh(olKvVoEm);SjVJvDnR(olKvVoEm);ibOAyjR(olKvVoEm,ROaVO);sExuWbFNP(olKvVoEm);SVcC(olK" ascii
    $s20 = "function lkNh(ApCQUK) {ApCQUK.open();}" fullword ascii

  condition:
    uint16(0) == 0x0f27 and
    8 of them
}