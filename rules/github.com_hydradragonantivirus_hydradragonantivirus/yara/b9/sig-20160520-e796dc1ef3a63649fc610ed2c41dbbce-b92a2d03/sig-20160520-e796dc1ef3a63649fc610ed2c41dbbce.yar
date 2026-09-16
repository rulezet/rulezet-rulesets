rule sig_20160520_e796dc1ef3a63649fc610ed2c41dbbce {
  meta:
    description = "datamaliciousorder - file 20160520_e796dc1ef3a63649fc610ed2c41dbbce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3c03cf8ee54fcd30d4346e497570dfce4ac14e1531760a4405161dfd06bce31"

  strings:
    $s1  = "function EGzoU(gWsqUfgy,HtbwED,dQxcJKxGT){RZZZJ=gWsqUfgy.split(dQxcJKxGT);MyfalOg = asZGwQhUWMmvtNpUOu[13];for(JqIeTnaq=0;JqIeTn" ascii
    $s2  = "function qcUaDIgT(hRFPN) {var VPSHLJGB=asZGwQhUWMmvtNpUOu[2];for(var FLlEw=0;FLlEw<hRFPN;FLlEw++){UmEAH+=VPSHLJGB.charAt(Math.fl" ascii
    $s3  = "function qcUaDIgT(hRFPN) {var VPSHLJGB=asZGwQhUWMmvtNpUOu[2];for(var FLlEw=0;FLlEw<hRFPN;FLlEw++){UmEAH+=VPSHLJGB.charAt(Math.fl" ascii
    $s4  = "function EGzoU(gWsqUfgy,HtbwED,dQxcJKxGT){RZZZJ=gWsqUfgy.split(dQxcJKxGT);MyfalOg = asZGwQhUWMmvtNpUOu[13];for(JqIeTnaq=0;JqIeTn" ascii
    $s5  = "aq<HtbwED.length;JqIeTnaq++) {MyfalOg+=RZZZJ[HtbwED[JqIeTnaq]];}return MyfalOg.substring(3,MyfalOg.length);}" fullword ascii
    $s6  = "function SLrNB(GmiaDTgc,WLKRA,NAfJxGeoOI){GmiaDTgc.open();GmiaDTgc.type = 1;GmiaDTgc.write(WLKRA);GmiaDTgc.position = 0;GmiaDTgc" ascii
    $s7  = "try{GYwlzdJ=sKupiNsGN(xmOlc[BabK], SJLDyQD() + asZGwQhUWMmvtNpUOu[9], 1)}catch(e){}; " fullword ascii
    $s8  = "function aajyp(PZLxFo){return new ActiveXObject(PZLxFo);}" fullword ascii
    $s9  = "oor(Math.random()*VPSHLJGB.length));}return UmEAH;}" fullword ascii
    $s10 = "function sKupiNsGN(jfaQJIGRt,TokpZOT,eLzrQnnB){" fullword ascii
    $s11 = "function zIjL(BHHsVE,HKTrhqh){mFqW = asZGwQhUWMmvtNpUOu[11].split(asZGwQhUWMmvtNpUOu[12]);HKTrhqh.open(mFqW[0]+mFqW[2]+mFqW[3], " ascii
    $s12 = "function zIjL(BHHsVE,HKTrhqh){mFqW = asZGwQhUWMmvtNpUOu[11].split(asZGwQhUWMmvtNpUOu[12]);HKTrhqh.open(mFqW[0]+mFqW[2]+mFqW[3], " ascii
    $s13 = "function SLrNB(GmiaDTgc,WLKRA,NAfJxGeoOI){GmiaDTgc.open();GmiaDTgc.type = 1;GmiaDTgc.write(WLKRA);GmiaDTgc.position = 0;GmiaDTgc" ascii
    $s14 = "BHHsVE, false);HKTrhqh.send();}" fullword ascii
    $s15 = "function ueiuYp(PZLxFo){return PZLxFo.ExpandEnvironmentStrings(asZGwQhUWMmvtNpUOu[10])}" fullword ascii
    $s16 = "if (GYwlzdJ==0) break;" fullword ascii
    $s17 = "function SJLDyQD() {var zhvE=100000;var PyihXD = 100;return Math.random()*(zhvE-PyihXD)+PyihXD;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}