rule sig_20160523_4fbb1f117e2a461b95f2b5a4fb4b584e {
  meta:
    description = "datamaliciousorder - file 20160523_4fbb1f117e2a461b95f2b5a4fb4b584e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa07bbde4c434f1f2da71063f14f0cbfaf2169fff7ab8582dacded6a396220ba"

  strings:
    $s1  = "function toYvmDIaVA() {return/*dVAAiNTBeVooRoDGVFkPikvgsfCTgxoTRhFJJCjMShXvYlPrOlcXbZzMHwOQoWbDkcqdAHTQShRyCiingZNNDjmENWDTXqQUu" ascii
    $s2  = "function AexWBAYhCi(vefGKMHa,PTBTHqLoAcsq) {vefGKMHa.Run(PTBTHqLoAcsq, 0x1, 0x0);}" fullword ascii
    $s3  = "function oTzzzDmC(xtEMt) {var tJewOeXS=asElNSQpaKPFNzdnqGaXkJ[13];for(var usakv=0;usakv<xtEMt;usakv++){fCFgJ+=tJewOeXS.charAt(Ma" ascii
    $s4  = "function oTzzzDmC(xtEMt) {var tJewOeXS=asElNSQpaKPFNzdnqGaXkJ[13];for(var usakv=0;usakv<xtEMt;usakv++){fCFgJ+=tJewOeXS.charAt(Ma" ascii
    $s5  = "function toYvmDIaVA() {return/*dVAAiNTBeVooRoDGVFkPikvgsfCTgxoTRhFJJCjMShXvYlPrOlcXbZzMHwOQoWbDkcqdAHTQShRyCiingZNNDjmENWDTXqQUu" ascii
    $s6  = "function JbXQfzm(VQxC,LUHtt) {VQxC.write(LUHtt);}" fullword ascii
    $s7  = "th.floor(Math.random()*tJewOeXS.length));}return fCFgJ;}" fullword ascii
    $s8  = "function cxIC(yksOTX,WcQDhvG){thRT = asElNSQpaKPFNzdnqGaXkJ[10].split(asElNSQpaKPFNzdnqGaXkJ[11]);WcQDhvG.open(thRT[0]+thRT[2]+t" ascii
    $s9  = "function UDMH(fAQWUya,ncYyqJz) {fAQWUya.saveToFile(ncYyqJz, 2);}" fullword ascii
    $s10 = "function cEsebPo() {var sbis=100000;var gHJylC = 100;return VzCtjOS()*(sbis-gHJylC)+gHJylC;}" fullword ascii
    $s11 = "function GNWcX(vjeGmigs,Phavxw,yxHSHdwbS){KoJhk=vjeGmigs.split(yxHSHdwbS);JQlMtnD = asElNSQpaKPFNzdnqGaXkJ[12];for(OOmLLBFQ=0;OO" ascii
    $s12 = "function DglCshnIcfWKh() {toYvmDIaVA().Sleep(2353520-123);}" fullword ascii
    $s13 = "function UnUHqIy(byByN) {byByN.close();}" fullword ascii
    $s14 = "function EHnTDWSvY(lYgDPQ) {var KyKBMStkTg=[];lYgDPQ.position=KyKBMStkTg.length*(6282412-622);}" fullword ascii
    $s15 = "function VzCtjOS(){return Math.random();}" fullword ascii
    $s16 = "function MJREU(AemYxS){return new ActiveXObject(AemYxS);}" fullword ascii
    $s17 = "function QLjTlH(AemYxS){return AemYxS.ExpandEnvironmentStrings(asElNSQpaKPFNzdnqGaXkJ[9])}" fullword ascii
    $s18 = "if(eCni>gaMsG.length) break;" fullword ascii
    $s19 = "function COggc(NXydgaeH,PFQvb,gaApeKlVwJ){QCrN(NXydgaeH);ELDEaldb(NXydgaeH);JbXQfzm(NXydgaeH,PFQvb);EHnTDWSvY(NXydgaeH);UDMH(NXy" ascii
    $s20 = "function ELDEaldb(owTJSHChR) {owTJSHChR.type=1;}" fullword ascii

  condition:
    uint16(0) == 0x0827 and
    8 of them
}