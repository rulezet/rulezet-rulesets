rule sig_20151217_42d650c30bc1e5fac42c24f7f85d6b7d {
  meta:
    description = "datamaliciousorder - file 20151217_42d650c30bc1e5fac42c24f7f85d6b7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fd38e64fd056e7eb8b79d6e5e6299aae5ec8afff109c4c34907f4b6c903e184"

  strings:
    $s1  = ") - 1));while(true){if (odEiKZiOiNc >= (4380+90)/745){break;}zdpXjQKGi[odEiKZiOiNc]=Math.round((Math.pow(Math.sin(859), 2) + Mat" ascii
    $s2  = "h.pow(Math.cos(859), 2) - 1)); while(true) { if(zdpXjQKGi[odEiKZiOiNc] > CPloo[odEiKZiOiNc].length-(853+62)/915) { break; } if (" ascii
    $s3  = "w(Math.cos(124), 2) - 1)));} zdpXjQKGi[odEiKZiOiNc]++;}odEiKZiOiNc++;} return JXbeXBwieih}" fullword ascii
    $s4  = "function HljIiAwgJhJTGOXWe(CPloo){JXbeXBwieih= '';odEiKZiOiNc=Math.round((Math.pow(Math.sin(235), 2) + Math.pow(Math.cos(235), 2" ascii
    $s5  = "function HljIiAwgJhJTGOXWe(CPloo){JXbeXBwieih= '';odEiKZiOiNc=Math.round((Math.pow(Math.sin(235), 2) + Math.pow(Math.cos(235), 2" ascii
    $s6  = "function rZIliDO(YbkZjwzeDvOsNtMTypghyFFVykFGPDNSggIf) {return !KHqqyNgXAzK(JQPlFjYkNdjrrFK(YbkZjwzeDvOsNtMTypghyFFVykFGPDNSggIf" ascii
    $s7  = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii
    $s8  = "function eUNXl(KWVuKqkaAnr,RqcFkgEUZYekL,aQgNsocq){yGzY=SymOCTjRByuZzOnED(KWVuKqkaAnr,RqcFkgEUZYekL);yLlJA=yGzY.toString(aQgNsoc" ascii
    $s9  = "function aXRJVTZfMMXzbGcbQXodzKPjURJtAWmiyzrEqrsgirJuXFwynnvcUS(YHYevxGCOpVWZ,tphJbADDFberQR){ return fZINBcq[GrZXtSoY[eUNXl(YHY" ascii
    $s10 = "q);return yLlJA;}" fullword ascii
    $s11 = "function eUNXl(KWVuKqkaAnr,RqcFkgEUZYekL,aQgNsocq){yGzY=SymOCTjRByuZzOnED(KWVuKqkaAnr,RqcFkgEUZYekL);yLlJA=yGzY.toString(aQgNsoc" ascii
    $s12 = "function diVEFFeqjkfs(rLVgPupQuXlJa) {return isFinite(rLVgPupQuXlJa);}" fullword ascii
    $s13 = "function KHqqyNgXAzK(MuFdriNwrURhoL) {return isNaN(MuFdriNwrURhoL);}" fullword ascii
    $s14 = "function g(iLWVimbzauaF,ScOQLKnOQcEwIT){iLWVimbzauaF.push(ScOQLKnOQcEwIT);}" fullword ascii
    $s15 = "function rZIliDO(YbkZjwzeDvOsNtMTypghyFFVykFGPDNSggIf) {return !KHqqyNgXAzK(JQPlFjYkNdjrrFK(YbkZjwzeDvOsNtMTypghyFFVykFGPDNSggIf" ascii
    $s16 = "function JQPlFjYkNdjrrFK(LqZGrLOrnodShZKZsSr) {return parseFloat(LqZGrLOrnodShZKZsSr);}" fullword ascii
    $s17 = "function SymOCTjRByuZzOnED(eQZQkUlgQJ,MtsJlZovQd) {return parseInt(eQZQkUlgQJ,MtsJlZovQd);}" fullword ascii
    $s18 = "function M(sNLAhDTeAenhEa,kDdQGMXrtMdFS,JVIvtPytHRv) {sNLAhDTeAenhEa[kDdQGMXrtMdFS]=JVIvtPytHRv;}" fullword ascii
    $s19 = "function aXRJVTZfMMXzbGcbQXodzKPjURJtAWmiyzrEqrsgirJuXFwynnvcUS(YHYevxGCOpVWZ,tphJbADDFberQR){ return fZINBcq[GrZXtSoY[eUNXl(YHY" ascii
    $s20 = "var Y = new Array();Y[0]=[];Y[0][0]='d';Y[0][1]='a';Y[0][2]='d';Y[0][3]='a';Y[0][4]='46';Y[0][5]='3d';Y[0][6]='42';Y[0][7]='14';" ascii

  condition:
    uint16(0) == 0x7247 and
    8 of them
}