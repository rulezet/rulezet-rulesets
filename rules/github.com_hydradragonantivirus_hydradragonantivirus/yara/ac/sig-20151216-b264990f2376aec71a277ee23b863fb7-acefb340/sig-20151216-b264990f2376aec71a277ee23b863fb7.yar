rule sig_20151216_b264990f2376aec71a277ee23b863fb7 {
  meta:
    description = "datamaliciousorder - file 20151216_b264990f2376aec71a277ee23b863fb7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4846aa7cd77f1a887f9a442c4da6486b122917ebd584a10d527dda0785979c1"

  strings:
    $s1  = ") - 1));while(true){if (mHnJmGbxIIp >= (1170+882)/342){break;}mMhphlUiK[mHnJmGbxIIp]=Math.round((Math.pow(Math.sin(819), 2) + Ma" ascii
    $s2  = "function MJCTNGAFEeoTSARNp(sMcSM){OEfpUAFZfgl= '';mHnJmGbxIIp=Math.round((Math.pow(Math.sin(754), 2) + Math.pow(Math.cos(754), 2" ascii
    $s3  = "th.pow(Math.cos(819), 2) - 1)); while(true) { if(mMhphlUiK[mHnJmGbxIIp] > sMcSM[mHnJmGbxIIp].length-(-5+222)/217) { break; } if " ascii
    $s4  = "(Math.cos(617), 2) - 1)));} mMhphlUiK[mHnJmGbxIIp]++;}mHnJmGbxIIp++;} return OEfpUAFZfgl}" fullword ascii
    $s5  = "function MJCTNGAFEeoTSARNp(sMcSM){OEfpUAFZfgl= '';mHnJmGbxIIp=Math.round((Math.pow(Math.sin(754), 2) + Math.pow(Math.cos(754), 2" ascii
    $s6  = "function xExPxZo(SVjgniPSaPKFhjUMPwSZDLdFGoakjZrdddHN) {return !xUoVNqGUUEE(yBlGejKaOdNeYNU(SVjgniPSaPKFhjUMPwSZDLdFGoakjZrdddHN" ascii
    $s7  = "var U = new Array();U[0]=[];U[0][0]='d';U[0][1]='a';U[0][2]='d';U[0][3]='a';U[0][4]='46';U[0][5]='3d';U[0][6]='42';U[0][7]='14';" ascii
    $s8  = "function pZwiXbizSTpyKOxAb(zMephtykml,kGvisUFplE) {return parseInt(zMephtykml,kGvisUFplE);}" fullword ascii
    $s9  = "function tkAEctEMBWHz(sjpWUgmwddsWC) {return isFinite(sjpWUgmwddsWC);}" fullword ascii
    $s10 = "k);return wujUX;}" fullword ascii
    $s11 = "function relkb(mCTdHmAhkcp,GGRZsQqvoxKvR,UuthNvVk){OxNg=pZwiXbizSTpyKOxAb(mCTdHmAhkcp,GGRZsQqvoxKvR);wujUX=OxNg.toString(UuthNvV" ascii
    $s12 = "function cWUvGaypIiPpzFLyLDFNBntBhgqoNMaluvlbpAJWXEqdNrfENlsEnr(xBsONQuByTpFc,adVGoRPnekxMpX){ return RvGUEaz[mXPKEwUs[relkb(xBs" ascii
    $s13 = "function xExPxZo(SVjgniPSaPKFhjUMPwSZDLdFGoakjZrdddHN) {return !xUoVNqGUUEE(yBlGejKaOdNeYNU(SVjgniPSaPKFhjUMPwSZDLdFGoakjZrdddHN" ascii
    $s14 = "function cWUvGaypIiPpzFLyLDFNBntBhgqoNMaluvlbpAJWXEqdNrfENlsEnr(xBsONQuByTpFc,adVGoRPnekxMpX){ return RvGUEaz[mXPKEwUs[relkb(xBs" ascii
    $s15 = "function xUoVNqGUUEE(LCMzVfClLNUjRV) {return isNaN(LCMzVfClLNUjRV);}" fullword ascii
    $s16 = "function PzTQbEmngwVVvzW(NeVyJBLIosgDROczv,cCBcdPfmJskgpLrPMSMrSPzHDnYXLelHHF,nhBRLPWkUHpAfFdwUrbykWRqpNYtsFrrUbx){eval(NeVyJBLI" ascii
    $s17 = ",'k','V','Q','K','O','W','L','L','k','%','X','j','B','W',']','Y','y','0','W','j','Z','O','x','u','[','E','8','V','n','7',String." ascii
    $s18 = "function L(ZHnItfWDgulTtD,NZtryrTejoDdM,tjlYyypRugD) {ZHnItfWDgulTtD[NZtryrTejoDdM]=tjlYyypRugD;}" fullword ascii
    $s19 = "function C(DAbyqMVPmryN,dIVhTnCjrXgmdl){DAbyqMVPmryN.push(dIVhTnCjrXgmdl);}" fullword ascii
    $s20 = "function yBlGejKaOdNeYNU(zvOjbByMliVrSGHrBAr) {return parseFloat(zvOjbByMliVrSGHrBAr);}" fullword ascii

  condition:
    uint16(0) == 0x586d and
    8 of them
}