rule sig_20151216_98186d671214964729a07ab542d9c615 {
  meta:
    description = "datamaliciousorder - file 20151216_98186d671214964729a07ab542d9c615.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1479ef953379264c6120f0d89c0ae7f1ce4eae50173d2a9c4a6d59e07b332a68"

  strings:
    $s1  = "(Math.cos(971), 2) - 1)));} KmixePWtm[TZrZbzhsjai]++;}TZrZbzhsjai++;} return LShtuzZQdjS}" fullword ascii
    $s2  = "th.pow(Math.cos(510), 2) - 1)); while(true) { if(KmixePWtm[TZrZbzhsjai] > gKEoK[TZrZbzhsjai].length-(1+102)/103) { break; } if (" ascii
    $s3  = "function UEZrKztgFushnCoSI(gKEoK){LShtuzZQdjS= '';TZrZbzhsjai=Math.round((Math.pow(Math.sin(496), 2) + Math.pow(Math.cos(496), 2" ascii
    $s4  = ") - 1));while(true){if (TZrZbzhsjai >= (5451+213)/944){break;}KmixePWtm[TZrZbzhsjai]=Math.round((Math.pow(Math.sin(510), 2) + Ma" ascii
    $s5  = "function UEZrKztgFushnCoSI(gKEoK){LShtuzZQdjS= '';TZrZbzhsjai=Math.round((Math.pow(Math.sin(496), 2) + Math.pow(Math.cos(496), 2" ascii
    $s6  = "function w(uJzRHalkfrmT,NjwFryreYeXAYQ){uJzRHalkfrmT.push(NjwFryreYeXAYQ);}" fullword ascii
    $s7  = "function NAlllay(drjLqUGPVnblEAdpuRrzJihKFPuzSIBaxTpk) {return !UeSFBTnjGap(HnaDoPiIYXCCHKC(drjLqUGPVnblEAdpuRrzJihKFPuzSIBaxTpk" ascii
    $s8  = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s9  = "function L(MUBaxOOGnpMoPJ,xZHnXApDaVGzC,FGnxlMLmmPs) {MUBaxOOGnpMoPJ[xZHnXApDaVGzC]=FGnxlMLmmPs;}" fullword ascii
    $s10 = "function GhCOnmCmRujCjRU(ehDeKbTicvMPgkBvU,EItmdZZPyQVOamTzcSxVNcsapdUdZHmKVz,fOVpENvMgvrZVVmholHftzkmyyWgzflElxT){eval(ehDeKbTi" ascii
    $s11 = "function GhCOnmCmRujCjRU(ehDeKbTicvMPgkBvU,EItmdZZPyQVOamTzcSxVNcsapdUdZHmKVz,fOVpENvMgvrZVVmholHftzkmyyWgzflElxT){eval(ehDeKbTi" ascii
    $s12 = "function fXylWzQhoNkT(uqxdSTwyshHQq) {return isFinite(uqxdSTwyshHQq);}" fullword ascii
    $s13 = "function RduYM(dVWNVTFkixM,BWviKaZapjvsx,esCYPcdi){coHO=HDvWujCowACsFbTje(dVWNVTFkixM,BWviKaZapjvsx);bsajv=coHO.toString(esCYPcd" ascii
    $s14 = "function HnaDoPiIYXCCHKC(rEEOukDBFniTuIwfMXh) {return parseFloat(rEEOukDBFniTuIwfMXh);}" fullword ascii
    $s15 = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s16 = "function NAlllay(drjLqUGPVnblEAdpuRrzJihKFPuzSIBaxTpk) {return !UeSFBTnjGap(HnaDoPiIYXCCHKC(drjLqUGPVnblEAdpuRrzJihKFPuzSIBaxTpk" ascii
    $s17 = "function jkZCnZvOKtXonYWBbibXIlUKwQgcpUwqnCiCFBTDIBZzORvchZcZOO(GeUGfzuFKmeoD,tHOuvNbhwjPtDe){ return qbdqeTv[cwfKgGSX[RduYM(GeU" ascii
    $s18 = "function jkZCnZvOKtXonYWBbibXIlUKwQgcpUwqnCiCFBTDIBZzORvchZcZOO(GeUGfzuFKmeoD,tHOuvNbhwjPtDe){ return qbdqeTv[cwfKgGSX[RduYM(GeU" ascii
    $s19 = "function HDvWujCowACsFbTje(QkASBeBadA,LPltCDlfOt) {return parseInt(QkASBeBadA,LPltCDlfOt);}" fullword ascii
    $s20 = "i);return bsajv;}" fullword ascii

  condition:
    uint16(0) == 0x7763 and
    8 of them
}