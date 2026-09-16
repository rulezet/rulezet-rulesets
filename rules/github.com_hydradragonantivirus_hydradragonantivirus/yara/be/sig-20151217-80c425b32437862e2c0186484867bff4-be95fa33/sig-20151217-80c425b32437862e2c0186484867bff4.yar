rule sig_20151217_80c425b32437862e2c0186484867bff4 {
  meta:
    description = "datamaliciousorder - file 20151217_80c425b32437862e2c0186484867bff4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad1104b5800e2b16e33e221f04aa9e9b6fb22bde57811fa45ddfc358932ef5a5"

  strings:
    $s1  = ") - 1));while(true){if (KBEpUcYqJiw >= (2929+257)/531){break;}ZuIfOocZk[KBEpUcYqJiw]=Math.round((Math.pow(Math.sin(501), 2) + Ma" ascii
    $s2  = "ow(Math.cos(923), 2) - 1)));} ZuIfOocZk[KBEpUcYqJiw]++;}KBEpUcYqJiw++;} return lYIpXMtdBqD}" fullword ascii
    $s3  = "function ehYNUOuJByLdwYhrA(WtxsG){lYIpXMtdBqD= '';KBEpUcYqJiw=Math.round((Math.pow(Math.sin(676), 2) + Math.pow(Math.cos(676), 2" ascii
    $s4  = "th.pow(Math.cos(501), 2) - 1)); while(true) { if(ZuIfOocZk[KBEpUcYqJiw] > WtxsG[KBEpUcYqJiw].length-(297+68)/365) { break; } if " ascii
    $s5  = "function ehYNUOuJByLdwYhrA(WtxsG){lYIpXMtdBqD= '';KBEpUcYqJiw=Math.round((Math.pow(Math.sin(676), 2) + Math.pow(Math.cos(676), 2" ascii
    $s6  = "function jDpUrNi(WtVolRluggOvrlIiaYTLBmejDVrAplMrulVD) {return !zPZwuInFVvy(kRsuWOCoXECvozf(WtVolRluggOvrlIiaYTLBmejDVrAplMrulVD" ascii
    $s7  = "var E = new Array();E[0]=[];E[0][0]='d';E[0][1]='a';E[0][2]='d';E[0][3]='a';E[0][4]='46';E[0][5]='3d';E[0][6]='42';E[0][7]='14';" ascii
    $s8  = "function ZncPygscSXHYZKrJKrSLeJNNkWPPGSuWVWNcrnMMqYSnsOFWYmkAlI(VZljpFRvObgSm,GgRVNsjFQBsIzy){ return ePfZYCE[rrmFAkPu[DCcPV(VZl" ascii
    $s9  = "function vFuExAngyXxmzuB(aCPhXuCOjkFqycifQ,eUJYwKttAVDtTNNMaBFKupvayfupWyMrDG,AocIrmqhQzNzLDVcbrkFBrgpZELUTzwPjIm){eval(aCPhXuCO" ascii
    $s10 = "function vFuExAngyXxmzuB(aCPhXuCOjkFqycifQ,eUJYwKttAVDtTNNMaBFKupvayfupWyMrDG,AocIrmqhQzNzLDVcbrkFBrgpZELUTzwPjIm){eval(aCPhXuCO" ascii
    $s11 = "function fxguFwnGYseCIfUPB(sBQeoBVGvo,YEEwmDwnzk) {return parseInt(sBQeoBVGvo,YEEwmDwnzk);}" fullword ascii
    $s12 = "function DCcPV(cmeLdlUKFQB,ZLZChpwIurplU,AspecDqM){wcWQ=fxguFwnGYseCIfUPB(cmeLdlUKFQB,ZLZChpwIurplU);lHpFZ=wcWQ.toString(AspecDq" ascii
    $s13 = "function b(qqVxnYIdMUHAyu,nAPFxJdFCnsnH,uGuBfGyxPOI) {qqVxnYIdMUHAyu[nAPFxJdFCnsnH]=uGuBfGyxPOI;}" fullword ascii
    $s14 = "function zPZwuInFVvy(CrxfwRzxXSnYjl) {return isNaN(CrxfwRzxXSnYjl);}" fullword ascii
    $s15 = ",'V',')','7','^','6','O','W','!','T','%','W','g','X',',','2','Y','n','\"','5','`','Z','N','@','9','F','[','N','L','c','m',String" ascii
    $s16 = "function ZncPygscSXHYZKrJKrSLeJNNkWPPGSuWVWNcrnMMqYSnsOFWYmkAlI(VZljpFRvObgSm,GgRVNsjFQBsIzy){ return ePfZYCE[rrmFAkPu[DCcPV(VZl" ascii
    $s17 = "var E = new Array();E[0]=[];E[0][0]='d';E[0][1]='a';E[0][2]='d';E[0][3]='a';E[0][4]='46';E[0][5]='3d';E[0][6]='42';E[0][7]='14';" ascii
    $s18 = "function DCcPV(cmeLdlUKFQB,ZLZChpwIurplU,AspecDqM){wcWQ=fxguFwnGYseCIfUPB(cmeLdlUKFQB,ZLZChpwIurplU);lHpFZ=wcWQ.toString(AspecDq" ascii
    $s19 = "function AmfTwlECbyEn(uvtXFheDjlxcJ) {return isFinite(uvtXFheDjlxcJ);}" fullword ascii
    $s20 = "function kRsuWOCoXECvozf(kKygWYCyABbfpSNhUOI) {return parseFloat(kKygWYCyABbfpSNhUOI);}" fullword ascii

  condition:
    uint16(0) == 0x7272 and
    8 of them
}