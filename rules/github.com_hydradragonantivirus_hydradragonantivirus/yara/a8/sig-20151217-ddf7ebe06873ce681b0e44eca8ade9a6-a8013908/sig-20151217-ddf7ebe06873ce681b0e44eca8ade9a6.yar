rule sig_20151217_ddf7ebe06873ce681b0e44eca8ade9a6 {
  meta:
    description = "datamaliciousorder - file 20151217_ddf7ebe06873ce681b0e44eca8ade9a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4717e46490a9b195e600c36aadd2c33f6ab3c0a24dcc55821ae6ce2a91085b23"

  strings:
    $s1  = "function wcQYFjGoCSiMYgMhP(Rnqcz){qndzdAvCNvL= '';BhlmUbOZYHS=Math.round((Math.pow(Math.sin(118), 2) + Math.pow(Math.cos(118), 2" ascii
    $s2  = ") - 1));while(true){if (BhlmUbOZYHS >= (3009+963)/662){break;}IZDjCDeFy[BhlmUbOZYHS]=Math.round((Math.pow(Math.sin(490), 2) + Ma" ascii
    $s3  = "(Math.cos(402), 2) - 1)));} IZDjCDeFy[BhlmUbOZYHS]++;}BhlmUbOZYHS++;} return qndzdAvCNvL}" fullword ascii
    $s4  = "th.pow(Math.cos(490), 2) - 1)); while(true) { if(IZDjCDeFy[BhlmUbOZYHS] > Rnqcz[BhlmUbOZYHS].length-(66+358)/424) { break; } if " ascii
    $s5  = "function wcQYFjGoCSiMYgMhP(Rnqcz){qndzdAvCNvL= '';BhlmUbOZYHS=Math.round((Math.pow(Math.sin(118), 2) + Math.pow(Math.cos(118), 2" ascii
    $s6  = "function sBDfLGDDnbfqkmjtoLEgrALuOgyFUSPyrXlgWLWHOYprbIODhxvgkG(ZeuVgjWQGSJLu,FfYginvLbHbhwW){ return lBSZXOT[kstKnqya[ywzUP(Zeu" ascii
    $s7  = "function sBDfLGDDnbfqkmjtoLEgrALuOgyFUSPyrXlgWLWHOYprbIODhxvgkG(ZeuVgjWQGSJLu,FfYginvLbHbhwW){ return lBSZXOT[kstKnqya[ywzUP(Zeu" ascii
    $s8  = "function KjIexSY(lMyjdPnTOTdBmtZBbzwMMIhxOnaPaTGcQBwN) {return !CJETHBpNvoY(SJNZtZEUCMTFrJF(lMyjdPnTOTdBmtZBbzwMMIhxOnaPaTGcQBwN" ascii
    $s9  = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s10 = "function bBMBrURYhuucWfu(kmNgioEkOvOVmtMcC,tAwuetlnMjjAECKAzuzaQFBimdyOuMFlJl,RJZzQuXVzyGuQLaNJorwzyZpPzkdAZcIzCu){eval(kmNgioEk" ascii
    $s11 = "U);return CwZOI;}" fullword ascii
    $s12 = "function jzzhlFJlxLsx(jUwjapkGvBEgj) {return isFinite(jUwjapkGvBEgj);}" fullword ascii
    $s13 = "function fLHVGaoLsEUpfrHso(kdbfUpurFZ,aeXfHShTGm) {return parseInt(kdbfUpurFZ,aeXfHShTGm);}" fullword ascii
    $s14 = "function CJETHBpNvoY(zaKXHhtxIBpHCy) {return isNaN(zaKXHhtxIBpHCy);}" fullword ascii
    $s15 = ",'5','[','V','M','j','@','R','M','W','7',' ','`','X','p','5','r','&','2','Y','Z','+','m','&','n','(','+','Q','[','{','e',String." ascii
    $s16 = "function KjIexSY(lMyjdPnTOTdBmtZBbzwMMIhxOnaPaTGcQBwN) {return !CJETHBpNvoY(SJNZtZEUCMTFrJF(lMyjdPnTOTdBmtZBbzwMMIhxOnaPaTGcQBwN" ascii
    $s17 = "var o = new Array();o[0]=[];o[0][0]='d';o[0][1]='a';o[0][2]='d';o[0][3]='a';o[0][4]='46';o[0][5]='3d';o[0][6]='42';o[0][7]='14';" ascii
    $s18 = "function q(UHmAVSGFXgbc,ccwHTUNYlqZFOv){UHmAVSGFXgbc.push(ccwHTUNYlqZFOv);}" fullword ascii
    $s19 = "function SJNZtZEUCMTFrJF(SZURAMBpNfCKPmUZnhH) {return parseFloat(SZURAMBpNfCKPmUZnhH);}" fullword ascii
    $s20 = "function ywzUP(zoBBcTctmGu,CyyiwgqtspVvs,wbPoVPXU){VZIA=fLHVGaoLsEUpfrHso(zoBBcTctmGu,CyyiwgqtspVvs);CwZOI=VZIA.toString(wbPoVPX" ascii

  condition:
    uint16(0) == 0x736b and
    8 of them
}