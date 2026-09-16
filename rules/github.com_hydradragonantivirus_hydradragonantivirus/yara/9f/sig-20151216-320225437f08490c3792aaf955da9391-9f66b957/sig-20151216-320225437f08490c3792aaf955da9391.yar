rule sig_20151216_320225437f08490c3792aaf955da9391 {
  meta:
    description = "datamaliciousorder - file 20151216_320225437f08490c3792aaf955da9391.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "711e8c774b58307af9c64f47358e6f93d5ebd89ca7f889e14e5d7e14634c8b9d"

  strings:
    $s1  = "th.pow(Math.cos(387), 2) - 1)); while(true) { if(LcfyooIrT[rxfqNLgSovd] > KTLIk[rxfqNLgSovd].length-(-231+478)/247) { break; } i" ascii
    $s2  = "(Math.cos(70), 2) - 1)));} LcfyooIrT[rxfqNLgSovd]++;}rxfqNLgSovd++;} return UqwgtXtUTij}" fullword ascii
    $s3  = ") - 1));while(true){if (rxfqNLgSovd >= (1463+229)/282){break;}LcfyooIrT[rxfqNLgSovd]=Math.round((Math.pow(Math.sin(387), 2) + Ma" ascii
    $s4  = "function YlBlefaPvyVoBjNpI(KTLIk){UqwgtXtUTij= '';rxfqNLgSovd=Math.round((Math.pow(Math.sin(592), 2) + Math.pow(Math.cos(592), 2" ascii
    $s5  = "function YlBlefaPvyVoBjNpI(KTLIk){UqwgtXtUTij= '';rxfqNLgSovd=Math.round((Math.pow(Math.sin(592), 2) + Math.pow(Math.cos(592), 2" ascii
    $s6  = "function igTHIGj(clOTlHcrYBgprWgUqQtygIvbJhyQGJpUbnOz) {return !gcvoxdIdMLQ(pOPBBSQNVmRoPya(clOTlHcrYBgprWgUqQtygIvbJhyQGJpUbnOz" ascii
    $s7  = "function LScjKRDrvPjiggN(wdZmICyayINBRTkWB,MLUqxULdqWaWkYqIFKCuZjxfypMPqdYtcR,FfKBFLMFlofMtHKebKPsSngRJxtgMTqxOIR){eval(wdZmICya" ascii
    $s8  = "function g(GDFMGSwNMhnc,RZdrAatGDphVYp){GDFMGSwNMhnc.push(RZdrAatGDphVYp);}" fullword ascii
    $s9  = "function FkapHrXnnGyK(bGVqsqnBJdQWA) {return isFinite(bGVqsqnBJdQWA);}" fullword ascii
    $s10 = "function OISSufkSQhqRGrVBD(YeDvaNObVL,VpRDzMSiSp) {return parseInt(YeDvaNObVL,VpRDzMSiSp);}" fullword ascii
    $s11 = "function aSAcQ(cwcnwgcCojQ,afPGtsiVrnRmF,ixYFMyRh){Rfaa=OISSufkSQhqRGrVBD(cwcnwgcCojQ,afPGtsiVrnRmF);ZtCsH=Rfaa.toString(ixYFMyR" ascii
    $s12 = "function aSAcQ(cwcnwgcCojQ,afPGtsiVrnRmF,ixYFMyRh){Rfaa=OISSufkSQhqRGrVBD(cwcnwgcCojQ,afPGtsiVrnRmF);ZtCsH=Rfaa.toString(ixYFMyR" ascii
    $s13 = "function qvAOCTrqzsSCcPmcMJqqBEflkeZBIsQBnBLLvttVdSBVudziNjtpZh(fDSgMKwTaVGRR,vzONwZDlUyIIAZ){ return RVaJeBy[HqiGWDbx[aSAcQ(fDS" ascii
    $s14 = "var d = new Array();d[0]=[];d[0][0]='d';d[0][1]='a';d[0][2]='d';d[0][3]='a';d[0][4]='46';d[0][5]='3d';d[0][6]='42';d[0][7]='14';" ascii
    $s15 = "function gcvoxdIdMLQ(IDdOYwmbEtivqK) {return isNaN(IDdOYwmbEtivqK);}" fullword ascii
    $s16 = "function igTHIGj(clOTlHcrYBgprWgUqQtygIvbJhyQGJpUbnOz) {return !gcvoxdIdMLQ(pOPBBSQNVmRoPya(clOTlHcrYBgprWgUqQtygIvbJhyQGJpUbnOz" ascii
    $s17 = "function qvAOCTrqzsSCcPmcMJqqBEflkeZBIsQBnBLLvttVdSBVudziNjtpZh(fDSgMKwTaVGRR,vzONwZDlUyIIAZ){ return RVaJeBy[HqiGWDbx[aSAcQ(fDS" ascii
    $s18 = "function pOPBBSQNVmRoPya(kEtmtXWMVaLAalFVNQS) {return parseFloat(kEtmtXWMVaLAalFVNQS);}" fullword ascii
    $s19 = "function LScjKRDrvPjiggN(wdZmICyayINBRTkWB,MLUqxULdqWaWkYqIFKCuZjxfypMPqdYtcR,FfKBFLMFlofMtHKebKPsSngRJxtgMTqxOIR){eval(wdZmICya" ascii
    $s20 = "h);return ZtCsH;}" fullword ascii

  condition:
    uint16(0) == 0x7148 and
    8 of them
}