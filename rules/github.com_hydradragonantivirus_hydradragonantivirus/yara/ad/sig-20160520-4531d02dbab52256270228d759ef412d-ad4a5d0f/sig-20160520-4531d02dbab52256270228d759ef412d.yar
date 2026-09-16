rule sig_20160520_4531d02dbab52256270228d759ef412d {
  meta:
    description = "datamaliciousorder - file 20160520_4531d02dbab52256270228d759ef412d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c17b37ea848ee61df84fc0f496833def580def622735d9bc574f18a769b615d"

  strings:
    $s1  = "function bhmFWlsA(ZRpix) {var PdiazgFV=SZSqHqLoUONId[2];for(var LveRS=0;LveRS<ZRpix;LveRS++){vKcLf+=PdiazgFV.charAt(Math.floor(M" ascii
    $s2  = "function bhmFWlsA(ZRpix) {var PdiazgFV=SZSqHqLoUONId[2];for(var LveRS=0;LveRS<ZRpix;LveRS++){vKcLf+=PdiazgFV.charAt(Math.floor(M" ascii
    $s3  = "ejlT.length;vFKgsOmC++) {oYEeBtF+=PfTCs[utejlT[vFKgsOmC]];}return oYEeBtF.substring(3,oYEeBtF.length);}" fullword ascii
    $s4  = "ath.random()*PdiazgFV.length));}return vKcLf;}" fullword ascii
    $s5  = "function kFCWNVKAR(tbMWBkvCD,uEFepED,ijnuuLXD){" fullword ascii
    $s6  = "if (sYGaIKO==0) break;" fullword ascii
    $s7  = "function DsYbq(LwEjYr){return new ActiveXObject(LwEjYr);}" fullword ascii
    $s8  = "function lAjV(QNJFfv,QkQScQi){UqaT = SZSqHqLoUONId[11].split(SZSqHqLoUONId[12]);QkQScQi.open(UqaT[0]+UqaT[2]+UqaT[3], QNJFfv, fa" ascii
    $s9  = "function lAjV(QNJFfv,QkQScQi){UqaT = SZSqHqLoUONId[11].split(SZSqHqLoUONId[12]);QkQScQi.open(UqaT[0]+UqaT[2]+UqaT[3], QNJFfv, fa" ascii
    $s10 = "function JnHrkId() {var NasI=100000;var ikElzt = 100;return Math.random()*(NasI-ikElzt)+ikElzt;}" fullword ascii
    $s11 = "function jmoDOe(LwEjYr){return LwEjYr.ExpandEnvironmentStrings(SZSqHqLoUONId[10])}" fullword ascii
    $s12 = "function sYLNi(RZKHLFTa,yAVZw,lUOxIvgSrC){RZKHLFTa.open();RZKHLFTa.type = 1;RZKHLFTa.write(yAVZw);RZKHLFTa.position = 0;RZKHLFTa" ascii
    $s13 = "function eSssg(kKazHNVq,utejlT,YiogCTrxn){PfTCs=kKazHNVq.split(YiogCTrxn);oYEeBtF = SZSqHqLoUONId[13];for(vFKgsOmC=0;vFKgsOmC<ut" ascii
    $s14 = "try{sYGaIKO=kFCWNVKAR(ZSvau[pfGb], JnHrkId() + SZSqHqLoUONId[9], 1)}catch(e){}; " fullword ascii
    $s15 = "function sYLNi(RZKHLFTa,yAVZw,lUOxIvgSrC){RZKHLFTa.open();RZKHLFTa.type = 1;RZKHLFTa.write(yAVZw);RZKHLFTa.position = 0;RZKHLFTa" ascii
    $s16 = "function eSssg(kKazHNVq,utejlT,YiogCTrxn){PfTCs=kKazHNVq.split(YiogCTrxn);oYEeBtF = SZSqHqLoUONId[13];for(vFKgsOmC=0;vFKgsOmC<ut" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}