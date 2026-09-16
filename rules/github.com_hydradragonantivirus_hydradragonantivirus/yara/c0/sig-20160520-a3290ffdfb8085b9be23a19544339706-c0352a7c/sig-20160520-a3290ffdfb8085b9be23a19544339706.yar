rule sig_20160520_a3290ffdfb8085b9be23a19544339706 {
  meta:
    description = "datamaliciousorder - file 20160520_a3290ffdfb8085b9be23a19544339706.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "114d11ab54a114c5ad29188d38188cff9c336f17625cb2957e96639150db7a15"

  strings:
    $s1  = "function UknemShx(LWXfO) {var zUTviJfd=ceMxWaSutl[2];for(var cDHLK=0;cDHLK<LWXfO;cDHLK++){mQRlV+=zUTviJfd.charAt(Math.floor(Math" ascii
    $s2  = "function UknemShx(LWXfO) {var zUTviJfd=ceMxWaSutl[2];for(var cDHLK=0;cDHLK<LWXfO;cDHLK++){mQRlV+=zUTviJfd.charAt(Math.floor(Math" ascii
    $s3  = "function MNSJg(TBCtpd){return new ActiveXObject(TBCtpd);}" fullword ascii
    $s4  = "function ZRQKijDMt(KFjDbfAyN,RyhLNIp,oqihmADv){" fullword ascii
    $s5  = "function aRACqs(TBCtpd){return TBCtpd.ExpandEnvironmentStrings(ceMxWaSutl[10])}" fullword ascii
    $s6  = "function KSqcUun() {var wGjm=100000;var TnKsEG = 100;return Math.random()*(wGjm-TnKsEG)+TnKsEG;}" fullword ascii
    $s7  = ".random()*zUTviJfd.length));}return mQRlV;}" fullword ascii
    $s8  = "function FUAQH(RxGOrApu,TNcpuO,FRuJiUQdx){UVAvr=RxGOrApu.split(FRuJiUQdx);NMQZuUc = ceMxWaSutl[13];for(NhbKqshF=0;NhbKqshF<TNcpu" ascii
    $s9  = "function YdSiY(nHqFsSnq,yKPfj,UqvDJGlnNe){nHqFsSnq.open();nHqFsSnq.type = 1;nHqFsSnq.write(yKPfj);nHqFsSnq.position = 0;nHqFsSnq" ascii
    $s10 = "function ZqsB(KtjqQy,xoqmUNH){OLFO = ceMxWaSutl[11].split(ceMxWaSutl[12]);xoqmUNH.open(OLFO[0]+OLFO[2]+OLFO[3], KtjqQy, false);x" ascii
    $s11 = "function ZqsB(KtjqQy,xoqmUNH){OLFO = ceMxWaSutl[11].split(ceMxWaSutl[12]);xoqmUNH.open(OLFO[0]+OLFO[2]+OLFO[3], KtjqQy, false);x" ascii
    $s12 = "function FUAQH(RxGOrApu,TNcpuO,FRuJiUQdx){UVAvr=RxGOrApu.split(FRuJiUQdx);NMQZuUc = ceMxWaSutl[13];for(NhbKqshF=0;NhbKqshF<TNcpu" ascii
    $s13 = "if (SCIwRuk==0) break;" fullword ascii
    $s14 = "O.length;NhbKqshF++) {NMQZuUc+=UVAvr[TNcpuO[NhbKqshF]];}return NMQZuUc.substring(3,NMQZuUc.length);}" fullword ascii
    $s15 = "try{SCIwRuk=ZRQKijDMt(bmEQZ[tZwK], KSqcUun() + ceMxWaSutl[9], 1)}catch(e){}; " fullword ascii
    $s16 = "function YdSiY(nHqFsSnq,yKPfj,UqvDJGlnNe){nHqFsSnq.open();nHqFsSnq.type = 1;nHqFsSnq.write(yKPfj);nHqFsSnq.position = 0;nHqFsSnq" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}