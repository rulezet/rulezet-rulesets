rule sig_20151216_1b4982d93376e3819b5124d4ee3b867a {
  meta:
    description = "datamaliciousorder - file 20151216_1b4982d93376e3819b5124d4ee3b867a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "875481b73c01502654b84415e09c88e4ca3b5893e256c33d14972041d55453a8"

  strings:
    $s1  = "function SbvXiBkToNzpYZVXm(Updci){eSPakVBYbPS= '';nQMkIcMuXHv=Math.round((Math.pow(Math.sin(822), 2) + Math.pow(Math.cos(822), 2" ascii
    $s2  = "th.cos(442), 2) - 1)));} ydJDGSjUJ[nQMkIcMuXHv]++;}nQMkIcMuXHv++;} return eSPakVBYbPS}" fullword ascii
    $s3  = "th.pow(Math.cos(540), 2) - 1)); while(true) { if(ydJDGSjUJ[nQMkIcMuXHv] > Updci[nQMkIcMuXHv].length-(317+617)/934) { break; } if" ascii
    $s4  = ") - 1));while(true){if (nQMkIcMuXHv >= (4529+469)/833){break;}ydJDGSjUJ[nQMkIcMuXHv]=Math.round((Math.pow(Math.sin(540), 2) + Ma" ascii
    $s5  = "function SbvXiBkToNzpYZVXm(Updci){eSPakVBYbPS= '';nQMkIcMuXHv=Math.round((Math.pow(Math.sin(822), 2) + Math.pow(Math.cos(822), 2" ascii
    $s6  = "function VhzQyXBwLZseHwiWQinQpfjrunJeSRUUMVksfmqgAbNPVNVynHlsyJ(kKFNfphOWjFlj,QjAjyATAXOHsNX){ return PVrVszH[TmMFIExO[iMtZu(kKF" ascii
    $s7  = "function VhzQyXBwLZseHwiWQinQpfjrunJeSRUUMVksfmqgAbNPVNVynHlsyJ(kKFNfphOWjFlj,QjAjyATAXOHsNX){ return PVrVszH[TmMFIExO[iMtZu(kKF" ascii
    $s8  = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s9  = "function iMtZu(ygzIMvnCCRp,dYUblYRcnyjII,NAPcLbic){mQEZ=QxWjTqJOUydqbCHAh(ygzIMvnCCRp,dYUblYRcnyjII);vhhFb=mQEZ.toString(NAPcLbi" ascii
    $s10 = "function D(ifGnUiwbjDoc,bPJxIspuhNfFJC){ifGnUiwbjDoc.push(bPJxIspuhNfFJC);}" fullword ascii
    $s11 = "function dnmwcDaoLyy(YecNhnrjQxknWE) {return isNaN(YecNhnrjQxknWE);}" fullword ascii
    $s12 = "function iMtZu(ygzIMvnCCRp,dYUblYRcnyjII,NAPcLbic){mQEZ=QxWjTqJOUydqbCHAh(ygzIMvnCCRp,dYUblYRcnyjII);vhhFb=mQEZ.toString(NAPcLbi" ascii
    $s13 = "function QxWjTqJOUydqbCHAh(RQparwoTee,zwGyvuKyvF) {return parseInt(RQparwoTee,zwGyvuKyvF);}" fullword ascii
    $s14 = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s15 = "function m(CEjPUmYFIvmsbG,eCKiXjPlMIcWz,LjZsVklQaTJ) {CEjPUmYFIvmsbG[eCKiXjPlMIcWz]=LjZsVklQaTJ;}" fullword ascii
    $s16 = "function ZTzsSXwllpHq(PgyGKnKSkPJgD) {return isFinite(PgyGKnKSkPJgD);}" fullword ascii
    $s17 = "c);return vhhFb;}" fullword ascii
    $s18 = "function ZEluwcJ(oPexSxwWbiBQTQQcdywKWgiJCgcnIhfyRdVC) {return !dnmwcDaoLyy(rXyEtCAnGtrsNbt(oPexSxwWbiBQTQQcdywKWgiJCgcnIhfyRdVC" ascii
    $s19 = "function GumpXjLQSfOQoFs(NEYMyGZVidqVOHCeV,tmllyrtrWsNfOdQBctlFojcghhecaiWsOG,cLicXiRlCIGUfKyaXzrkvPMmkABAJfbqziN){eval(NEYMyGZV" ascii
    $s20 = "function GumpXjLQSfOQoFs(NEYMyGZVidqVOHCeV,tmllyrtrWsNfOdQBctlFojcghhecaiWsOG,cLicXiRlCIGUfKyaXzrkvPMmkABAJfbqziN){eval(NEYMyGZV" ascii

  condition:
    uint16(0) == 0x6d54 and
    8 of them
}