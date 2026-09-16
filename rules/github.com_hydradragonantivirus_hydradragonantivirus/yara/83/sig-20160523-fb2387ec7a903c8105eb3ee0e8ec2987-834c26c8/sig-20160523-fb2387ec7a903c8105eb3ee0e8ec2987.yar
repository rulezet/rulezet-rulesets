rule sig_20160523_fb2387ec7a903c8105eb3ee0e8ec2987 {
  meta:
    description = "datamaliciousorder - file 20160523_fb2387ec7a903c8105eb3ee0e8ec2987.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81ff46516f68739d92efe1823d1f272c9eaba375694974be38acbad72aebc109"

  strings:
    $s1  = "function msPCKHdRvM() {return/*ivkmweHgBAiqqSIpEypDqxpyVVJgTlxcGClrMnVECzDTZpEPdQPNGPzNHcKIaZnnTWCkEnwekkJzFuhLqGIMeoIYdXXVPtyKe" ascii
    $s2  = "function fjJhHvhZlg(CCybEzDS,uYXMdUHaFCNf) {CCybEzDS.Run(uYXMdUHaFCNf, 0x1, 0x0);}" fullword ascii
    $s3  = "function JrwLosuy(tzjXM) {var MEqsgLLb=MgfbiRvJpNtHzz[13];for(var PisFU=0;PisFU<tzjXM;PisFU++){hSzts+=MEqsgLLb.charAt(Math.floor" ascii
    $s4  = "function JrwLosuy(tzjXM) {var MEqsgLLb=MgfbiRvJpNtHzz[13];for(var PisFU=0;PisFU<tzjXM;PisFU++){hSzts+=MEqsgLLb.charAt(Math.floor" ascii
    $s5  = "bhxNk.length;XeTwfmzj++) {fohkilU+=UBDvc[AbhxNk[XeTwfmzj]];}return fohkilU.substring(3,fohkilU.length);}" fullword ascii
    $s6  = "function Ndcq(tzwAvye,euzUymz) {tzwAvye.saveToFile(euzUymz, 2);}" fullword ascii
    $s7  = "function BJopG(FSyUuJyu,COVFd,pwQYZTMjKy){IoAe(FSyUuJyu);tisugHyW(FSyUuJyu);zpeesvp(FSyUuJyu,COVFd);LjIYetbMC(FSyUuJyu);Ndcq(FSy" ascii
    $s8  = "(Math.random()*MEqsgLLb.length));}return hSzts;}" fullword ascii
    $s9  = "false);PzQpZqm.send();}" fullword ascii
    $s10 = "function SNIx(efoGNb,PzQpZqm){GaXn = MgfbiRvJpNtHzz[10].split(MgfbiRvJpNtHzz[11]);PzQpZqm.open(GaXn[0]+GaXn[2]+GaXn[3], efoGNb, " ascii
    $s11 = "function SNIx(efoGNb,PzQpZqm){GaXn = MgfbiRvJpNtHzz[10].split(MgfbiRvJpNtHzz[11]);PzQpZqm.open(GaXn[0]+GaXn[2]+GaXn[3], efoGNb, " ascii
    $s12 = "function HvhoWir(DatiL) {DatiL.close();}" fullword ascii
    $s13 = "function zpeesvp(TZiq,jJubr) {TZiq.write(jJubr);}" fullword ascii
    $s14 = "function tisugHyW(jAMyoWZqu) {jAMyoWZqu.type=1;}" fullword ascii
    $s15 = "function msPCKHdRvM() {return/*ivkmweHgBAiqqSIpEypDqxpyVVJgTlxcGClrMnVECzDTZpEPdQPNGPzNHcKIaZnnTWCkEnwekkJzFuhLqGIMeoIYdXXVPtyKe" ascii
    $s16 = "function BJopG(FSyUuJyu,COVFd,pwQYZTMjKy){IoAe(FSyUuJyu);tisugHyW(FSyUuJyu);zpeesvp(FSyUuJyu,COVFd);LjIYetbMC(FSyUuJyu);Ndcq(FSy" ascii
    $s17 = "function IGBxh(PIaDJfGM,AbhxNk,EDOnaWiJo){UBDvc=PIaDJfGM.split(EDOnaWiJo);fohkilU = MgfbiRvJpNtHzz[12];for(XeTwfmzj=0;XeTwfmzj<A" ascii
    $s18 = "function CYnkPw(dMlAkc){return dMlAkc.ExpandEnvironmentStrings(MgfbiRvJpNtHzz[9])}" fullword ascii
    $s19 = "function IGBxh(PIaDJfGM,AbhxNk,EDOnaWiJo){UBDvc=PIaDJfGM.split(EDOnaWiJo);fohkilU = MgfbiRvJpNtHzz[12];for(XeTwfmzj=0;XeTwfmzj<A" ascii
    $s20 = "function IoAe(sxpvlq) {sxpvlq.open();}" fullword ascii

  condition:
    uint16(0) == 0x1127 and
    8 of them
}