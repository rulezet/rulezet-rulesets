rule sig_20151216_34e1bd7bed68029c425e55f6d9b03162 {
  meta:
    description = "datamaliciousorder - file 20151216_34e1bd7bed68029c425e55f6d9b03162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45204548b1aeeb23d31e6c2d173268765622f225f9d2334bc7a46c9e82154a1c"

  strings:
    $s1  = ") - 1));while(true){if (gkrkMLESvlf >= (1811+403)/369){break;}HABRENNyq[gkrkMLESvlf]=Math.round((Math.pow(Math.sin(358), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(358), 2) - 1)); while(true) { if(HABRENNyq[gkrkMLESvlf] > fPHay[gkrkMLESvlf].length-(-786+790)/4) { break; } if " ascii
    $s3  = "ow(Math.cos(917), 2) - 1)));} HABRENNyq[gkrkMLESvlf]++;}gkrkMLESvlf++;} return YuehFDSIbjX}" fullword ascii
    $s4  = "function JyBQQwwVrKPtzmVxx(fPHay){YuehFDSIbjX= '';gkrkMLESvlf=Math.round((Math.pow(Math.sin(457), 2) + Math.pow(Math.cos(457), 2" ascii
    $s5  = "function JyBQQwwVrKPtzmVxx(fPHay){YuehFDSIbjX= '';gkrkMLESvlf=Math.round((Math.pow(Math.sin(457), 2) + Math.pow(Math.cos(457), 2" ascii
    $s6  = "function eqHubpQ(SLgbwWQdDPrLUEkGttrLZLJuExPgMcCmAbic) {return !JoAnesYKFOt(qAuBOzQlZIaYvoA(SLgbwWQdDPrLUEkGttrLZLJuExPgMcCmAbic" ascii
    $s7  = "function vOGEF(HTclXklfdEa,yFvqecEUFpcbc,CdbvoZwZ){OLXG=CktDHncjyjkGnNoJt(HTclXklfdEa,yFvqecEUFpcbc);GKmOp=OLXG.toString(CdbvoZw" ascii
    $s8  = "function jISVsUnJtliDgmQ(CueBmZHLfGfpKDyvB,MpnNWVPFndEGRAobXFaRQbXHZqvRVmOoZn,nFZJpXhlwBzRBttLmrlvKFCvRKDLRueALOC){eval(CueBmZHL" ascii
    $s9  = "function J(ZaSnuirnZyOh,TAvQoTCzxashiC){ZaSnuirnZyOh.push(TAvQoTCzxashiC);}" fullword ascii
    $s10 = "function jISVsUnJtliDgmQ(CueBmZHLfGfpKDyvB,MpnNWVPFndEGRAobXFaRQbXHZqvRVmOoZn,nFZJpXhlwBzRBttLmrlvKFCvRKDLRueALOC){eval(CueBmZHL" ascii
    $s11 = "function JoAnesYKFOt(HrUuZIKlZsjsuE) {return isNaN(HrUuZIKlZsjsuE);}" fullword ascii
    $s12 = "function CktDHncjyjkGnNoJt(sQNysBTNPB,GJNovgYufZ) {return parseInt(sQNysBTNPB,GJNovgYufZ);}" fullword ascii
    $s13 = "function qAuBOzQlZIaYvoA(DRDcoivmKeLFOzSzoRp) {return parseFloat(DRDcoivmKeLFOzSzoRp);}" fullword ascii
    $s14 = "var n = new Array();n[0]=[];n[0][0]='d';n[0][1]='a';n[0][2]='d';n[0][3]='a';n[0][4]='46';n[0][5]='3d';n[0][6]='42';n[0][7]='14';" ascii
    $s15 = "var n = new Array();n[0]=[];n[0][0]='d';n[0][1]='a';n[0][2]='d';n[0][3]='a';n[0][4]='46';n[0][5]='3d';n[0][6]='42';n[0][7]='14';" ascii
    $s16 = "function eqHubpQ(SLgbwWQdDPrLUEkGttrLZLJuExPgMcCmAbic) {return !JoAnesYKFOt(qAuBOzQlZIaYvoA(SLgbwWQdDPrLUEkGttrLZLJuExPgMcCmAbic" ascii
    $s17 = "function W(GrznCNrSpGindk,mRnWYQcfJLppu,DKheHhuwwDd) {GrznCNrSpGindk[mRnWYQcfJLppu]=DKheHhuwwDd;}" fullword ascii
    $s18 = "function vOGEF(HTclXklfdEa,yFvqecEUFpcbc,CdbvoZwZ){OLXG=CktDHncjyjkGnNoJt(HTclXklfdEa,yFvqecEUFpcbc);GKmOp=OLXG.toString(CdbvoZw" ascii
    $s19 = "Z);return GKmOp;}" fullword ascii
    $s20 = "function bSoSaCwVIwtO(gOyRFmkutWWwv) {return isFinite(gOyRFmkutWWwv);}" fullword ascii

  condition:
    uint16(0) == 0x6f58 and
    8 of them
}