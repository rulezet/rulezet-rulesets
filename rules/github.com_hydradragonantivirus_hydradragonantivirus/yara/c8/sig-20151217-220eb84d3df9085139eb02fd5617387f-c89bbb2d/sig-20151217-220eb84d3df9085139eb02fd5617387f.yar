rule sig_20151217_220eb84d3df9085139eb02fd5617387f {
  meta:
    description = "datamaliciousorder - file 20151217_220eb84d3df9085139eb02fd5617387f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1f82da35171dcdf605f202e2cd9f7cf06f0099fe367c7422ee28d8ef2c97a42"

  strings:
    $s1  = ") - 1));while(true){if (IbsTclIgPEu >= (2439+255)/449){break;}BGOqHytKO[IbsTclIgPEu]=Math.round((Math.pow(Math.sin(937), 2) + Ma" ascii
    $s2  = "(Math.cos(402), 2) - 1)));} BGOqHytKO[IbsTclIgPEu]++;}IbsTclIgPEu++;} return OvTFZErgZva}" fullword ascii
    $s3  = "function MhAtHiSZnXJpBXRZR(jwVRs){OvTFZErgZva= '';IbsTclIgPEu=Math.round((Math.pow(Math.sin(529), 2) + Math.pow(Math.cos(529), 2" ascii
    $s4  = "th.pow(Math.cos(937), 2) - 1)); while(true) { if(BGOqHytKO[IbsTclIgPEu] > jwVRs[IbsTclIgPEu].length-(-6+208)/202) { break; } if " ascii
    $s5  = "function MhAtHiSZnXJpBXRZR(jwVRs){OvTFZErgZva= '';IbsTclIgPEu=Math.round((Math.pow(Math.sin(529), 2) + Math.pow(Math.cos(529), 2" ascii
    $s6  = "function kWOqYbT(sopTKJFPQlIyAMxSWHRoismUwGhhfjLIBCNs) {return !YfEMCwcLUdL(OLjzaSudLYrSiCh(sopTKJFPQlIyAMxSWHRoismUwGhhfjLIBCNs" ascii
    $s7  = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s8  = "function YrsyLtFHKZYq(ZDlEdzUdbtGjb) {return isFinite(ZDlEdzUdbtGjb);}" fullword ascii
    $s9  = "function M(kACHbWUxwzdj,uTmMcSNnadDFCp){kACHbWUxwzdj.push(uTmMcSNnadDFCp);}" fullword ascii
    $s10 = "function godysaYMGgiYDrfsc(RoepYdacXu,VWsmMrqzDs) {return parseInt(RoepYdacXu,VWsmMrqzDs);}" fullword ascii
    $s11 = "function KPzpQ(RbpRfbpnyIo,whQPvZRXWHDPn,KGvAyWuI){ILin=godysaYMGgiYDrfsc(RbpRfbpnyIo,whQPvZRXWHDPn);YaTPd=ILin.toString(KGvAyWu" ascii
    $s12 = "function OsWHphMvLenitKEVmDLOxNdBDaCROQaNnDiuhffRwJSOeEMMaQriTH(eAusRApzSizlC,ybUkrPtegNEfen){ return tHItYKJ[rVHijEDF[KPzpQ(eAu" ascii
    $s13 = "function OLjzaSudLYrSiCh(OYhJURbTYfwwiEhiWDJ) {return parseFloat(OYhJURbTYfwwiEhiWDJ);}" fullword ascii
    $s14 = "function KPzpQ(RbpRfbpnyIo,whQPvZRXWHDPn,KGvAyWuI){ILin=godysaYMGgiYDrfsc(RbpRfbpnyIo,whQPvZRXWHDPn);YaTPd=ILin.toString(KGvAyWu" ascii
    $s15 = "function eVqLNbxLKqQzXsH(lRhHQZsOiNXITsRAv,oRmevRNBTPQIRTjXqyRggvUEVDYRATqAWj,qyIWYogNRtoKIqZkKwdqnpuAQoqcNLezrEB){eval(lRhHQZsO" ascii
    $s16 = "I);return YaTPd;}" fullword ascii
    $s17 = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s18 = "function eVqLNbxLKqQzXsH(lRhHQZsOiNXITsRAv,oRmevRNBTPQIRTjXqyRggvUEVDYRATqAWj,qyIWYogNRtoKIqZkKwdqnpuAQoqcNLezrEB){eval(lRhHQZsO" ascii
    $s19 = "function O(dhoSnCRsUNZwFG,stHIDSsyAYVXz,xDtfSOaGRdt) {dhoSnCRsUNZwFG[stHIDSsyAYVXz]=xDtfSOaGRdt;}" fullword ascii
    $s20 = "function YfEMCwcLUdL(LrfpqbdteReRHu) {return isNaN(LrfpqbdteReRHu);}" fullword ascii

  condition:
    uint16(0) == 0x5672 and
    8 of them
}