rule sig_20151216_6a0699dfe71ed02aed0d1f15fc6872e3 {
  meta:
    description = "datamaliciousorder - file 20151216_6a0699dfe71ed02aed0d1f15fc6872e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "caa3e7f75cdce0f3ab6cc2ce7a89d6ef37a9dfd251d0630e489aabc5dba5de5c"

  strings:
    $s1  = "w(Math.cos(48), 2) - 1)));} oeWbJVhQF[kNStTrwoqKW]++;}kNStTrwoqKW++;} return ebxSMyDlpny}" fullword ascii
    $s2  = "th.pow(Math.cos(790), 2) - 1)); while(true) { if(oeWbJVhQF[kNStTrwoqKW] > nWpBR[kNStTrwoqKW].length-(390+114)/504) { break; } if" ascii
    $s3  = ") - 1));while(true){if (kNStTrwoqKW >= (2423+391)/469){break;}oeWbJVhQF[kNStTrwoqKW]=Math.round((Math.pow(Math.sin(790), 2) + Ma" ascii
    $s4  = "function ncquwEOGLxZNzCoqE(nWpBR){ebxSMyDlpny= '';kNStTrwoqKW=Math.round((Math.pow(Math.sin(611), 2) + Math.pow(Math.cos(611), 2" ascii
    $s5  = "function ncquwEOGLxZNzCoqE(nWpBR){ebxSMyDlpny= '';kNStTrwoqKW=Math.round((Math.pow(Math.sin(611), 2) + Math.pow(Math.cos(611), 2" ascii
    $s6  = "function JPjkUNs(ngKlyFyELuWNfWyoJnKVItDxdZvaJFXIuTuD) {return !uHIWVCyBpMZ(MNMZJyrRdEiYfrj(ngKlyFyELuWNfWyoJnKVItDxdZvaJFXIuTuD" ascii
    $s7  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s8  = "function uHIWVCyBpMZ(gYFQJUZKqXtDgn) {return isNaN(gYFQJUZKqXtDgn);}" fullword ascii
    $s9  = "p);return izcKZ;}" fullword ascii
    $s10 = "function vPYXI(vVydkRWeifj,eZQJFzJQjDoQL,YgjJrSEp){lwGM=VCRbmCkbxqWSYPkCD(vVydkRWeifj,eZQJFzJQjDoQL);izcKZ=lwGM.toString(YgjJrSE" ascii
    $s11 = "function j(EkIwsLETxIcvnA,FfkeqVQNRKGmJ,nPnPTmwHnuK) {EkIwsLETxIcvnA[FfkeqVQNRKGmJ]=nPnPTmwHnuK;}" fullword ascii
    $s12 = "function CzyQhiBkZmZkPTc(dcfDdjUBcOaKJOeor,qICdFSvqEyCgeFCzpJvmnsiOrKNohXlVhr,VPLKRmdUYAKYTihmAvJxsUNcvSUYEeSRsac){eval(dcfDdjUB" ascii
    $s13 = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s14 = "function n(nrtoVpJbFrwl,oXiJTYqLXuxTfh){nrtoVpJbFrwl.push(oXiJTYqLXuxTfh);}" fullword ascii
    $s15 = "function OtwWHGPxjCWr(GbuBVvWWdctkz) {return isFinite(GbuBVvWWdctkz);}" fullword ascii
    $s16 = "function MNMZJyrRdEiYfrj(MsUsQzVSMFLpKzuIGmv) {return parseFloat(MsUsQzVSMFLpKzuIGmv);}" fullword ascii
    $s17 = "function JPjkUNs(ngKlyFyELuWNfWyoJnKVItDxdZvaJFXIuTuD) {return !uHIWVCyBpMZ(MNMZJyrRdEiYfrj(ngKlyFyELuWNfWyoJnKVItDxdZvaJFXIuTuD" ascii
    $s18 = "function CzyQhiBkZmZkPTc(dcfDdjUBcOaKJOeor,qICdFSvqEyCgeFCzpJvmnsiOrKNohXlVhr,VPLKRmdUYAKYTihmAvJxsUNcvSUYEeSRsac){eval(dcfDdjUB" ascii
    $s19 = "function VCRbmCkbxqWSYPkCD(yJRPzYvuFh,fSzsxJRIIV) {return parseInt(yJRPzYvuFh,fSzsxJRIIV);}" fullword ascii
    $s20 = "function vPYXI(vVydkRWeifj,eZQJFzJQjDoQL,YgjJrSEp){lwGM=VCRbmCkbxqWSYPkCD(vVydkRWeifj,eZQJFzJQjDoQL);izcKZ=lwGM.toString(YgjJrSE" ascii

  condition:
    uint16(0) == 0x4a68 and
    8 of them
}