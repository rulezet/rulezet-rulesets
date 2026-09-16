rule sig_20151217_d4d2d2b66dadc7d0cc0fbd58be7a9762 {
  meta:
    description = "datamaliciousorder - file 20151217_d4d2d2b66dadc7d0cc0fbd58be7a9762.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "097700817181c2f024604148b26b04a759272c25d0736019a25a1d1110405672"

  strings:
    $s1  = "Math.cos(181), 2) - 1)));} KHfcfrbVL[mZucivyfEMV]++;}mZucivyfEMV++;} return UYglCZZnCIS}" fullword ascii
    $s2  = ".pow(Math.cos(509), 2) - 1)); while(true) { if(KHfcfrbVL[mZucivyfEMV] > WYZtv[mZucivyfEMV].length-(758+64)/822) { break; } if (G" ascii
    $s3  = "function rVLGMvQUsQkKurckh(WYZtv){UYglCZZnCIS= '';mZucivyfEMV=Math.round((Math.pow(Math.sin(98), 2) + Math.pow(Math.cos(98), 2) " ascii
    $s4  = "function rVLGMvQUsQkKurckh(WYZtv){UYglCZZnCIS= '';mZucivyfEMV=Math.round((Math.pow(Math.sin(98), 2) + Math.pow(Math.cos(98), 2) " ascii
    $s5  = "- 1));while(true){if (mZucivyfEMV >= (4148+904)/842){break;}KHfcfrbVL[mZucivyfEMV]=Math.round((Math.pow(Math.sin(509), 2) + Math" ascii
    $s6  = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s7  = "m);return xeiYc;}" fullword ascii
    $s8  = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s9  = "function D(ozLUFHvXNvFb,HFEJwPVCSqWbhy){ozLUFHvXNvFb.push(HFEJwPVCSqWbhy);}" fullword ascii
    $s10 = "function pKZHibotbRC(WTSdBCWPCcvpSc) {return isNaN(WTSdBCWPCcvpSc);}" fullword ascii
    $s11 = "function hUsZRQjPyNqwZLP(LlyLZthrKyfqLvLSM,ZumhTsMItlxxiAxZfGMYDRSPgzfhfVThye,anApMJlqcCTnYMmbnIUdUSkohShAaJJhHsn){eval(LlyLZthr" ascii
    $s12 = "function cEOrXRQaerHbJez(soVXcYDwthrigBleccl) {return parseFloat(soVXcYDwthrigBleccl);}" fullword ascii
    $s13 = "function rwAoihtMKTjm(jSZAnyEKpPxDZ) {return isFinite(jSZAnyEKpPxDZ);}" fullword ascii
    $s14 = "function hUsZRQjPyNqwZLP(LlyLZthrKyfqLvLSM,ZumhTsMItlxxiAxZfGMYDRSPgzfhfVThye,anApMJlqcCTnYMmbnIUdUSkohShAaJJhHsn){eval(LlyLZthr" ascii
    $s15 = "function x(zOCeeaFVWpevOD,MSEsTtKsZgKpq,QDkzwaQmZjS) {zOCeeaFVWpevOD[MSEsTtKsZgKpq]=QDkzwaQmZjS;}" fullword ascii
    $s16 = "function GUkNvse(qJaCCiLyYaiSVJDKcaXlCwYvvGnLfrZegPna) {return !pKZHibotbRC(cEOrXRQaerHbJez(qJaCCiLyYaiSVJDKcaXlCwYvvGnLfrZegPna" ascii
    $s17 = "function pGVoohStenDYYSQdSQrFdHBQABLgWVWuAwJLcaqLlxQLYyejYFHZYe(SBLflxnwdTJjg,yGfKuqUJZGOVFN){ return JQxapju[imxwKBaL[khMNx(SBL" ascii
    $s18 = "function pGVoohStenDYYSQdSQrFdHBQABLgWVWuAwJLcaqLlxQLYyejYFHZYe(SBLflxnwdTJjg,yGfKuqUJZGOVFN){ return JQxapju[imxwKBaL[khMNx(SBL" ascii
    $s19 = "function khMNx(SCPXBdPdjPY,dnLFDMcQOZrQe,fLweWIUm){gkMl=iCAaBRvzhMEkZbrYC(SCPXBdPdjPY,dnLFDMcQOZrQe);xeiYc=gkMl.toString(fLweWIU" ascii
    $s20 = "function GUkNvse(qJaCCiLyYaiSVJDKcaXlCwYvvGnLfrZegPna) {return !pKZHibotbRC(cEOrXRQaerHbJez(qJaCCiLyYaiSVJDKcaXlCwYvvGnLfrZegPna" ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}