rule sig_20151216_7be4ad748afff40eded3f450dc11c8d2 {
  meta:
    description = "datamaliciousorder - file 20151216_7be4ad748afff40eded3f450dc11c8d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d9d608e43375c4fb198420eb22fb0d6815b30f874168c2d51bf441ea68b5972"

  strings:
    $s1  = "th.pow(Math.cos(105), 2) - 1)); while(true) { if(ywVpfdkma[EPIzjXaZwlG] > qqISV[EPIzjXaZwlG].length-(-532+684)/152) { break; } i" ascii
    $s2  = ") - 1));while(true){if (EPIzjXaZwlG >= (2793+801)/599){break;}ywVpfdkma[EPIzjXaZwlG]=Math.round((Math.pow(Math.sin(105), 2) + Ma" ascii
    $s3  = "pow(Math.cos(884), 2) - 1)));} ywVpfdkma[EPIzjXaZwlG]++;}EPIzjXaZwlG++;} return AeXFZIePCVp}" fullword ascii
    $s4  = "function NroSyOEoZJQYgHfQa(qqISV){AeXFZIePCVp= '';EPIzjXaZwlG=Math.round((Math.pow(Math.sin(683), 2) + Math.pow(Math.cos(683), 2" ascii
    $s5  = "xWrFrdmLbcXzfxOKZtSKwgDQPdsEWlIrDUy([qqISV[EPIzjXaZwlG][ywVpfdkma[EPIzjXaZwlG]]], Math.round((Math.pow(Math.sin(884), 2) + Math." ascii
    $s6  = "function NroSyOEoZJQYgHfQa(qqISV){AeXFZIePCVp= '';EPIzjXaZwlG=Math.round((Math.pow(Math.sin(683), 2) + Math.pow(Math.cos(683), 2" ascii
    $s7  = "function gayQiAcVvzWwfnW(IZiozNglisIeyrnon,OCjpbxbjrOPCfeWTAmvyBGUIdkfThtPcye,hZUjSpyiurayfKbjVSLewnHXXswGWKrJgVp){eval(IZiozNgl" ascii
    $s8  = "function gayQiAcVvzWwfnW(IZiozNglisIeyrnon,OCjpbxbjrOPCfeWTAmvyBGUIdkfThtPcye,hZUjSpyiurayfKbjVSLewnHXXswGWKrJgVp){eval(IZiozNgl" ascii
    $s9  = "function iFbFVkM(leSQVWqHidGaUSpiFhsMCyCBTQbymQnwpQzm) {return !YhVhmMsLRUk(TmtyAgKEgExBmrs(leSQVWqHidGaUSpiFhsMCyCBTQbymQnwpQzm" ascii
    $s10 = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s11 = "function uhwkG(yuSfXKKvNkc,AwEQqjWuiqoDP,QuwuGveZ){Xzyh=DKxpViOReMXJProrS(yuSfXKKvNkc,AwEQqjWuiqoDP);pzpII=Xzyh.toString(QuwuGve" ascii
    $s12 = "var T = new Array();T[0]=[];T[0][0]='d';T[0][1]='a';T[0][2]='d';T[0][3]='a';T[0][4]='46';T[0][5]='3d';T[0][6]='42';T[0][7]='14';" ascii
    $s13 = "function iFbFVkM(leSQVWqHidGaUSpiFhsMCyCBTQbymQnwpQzm) {return !YhVhmMsLRUk(TmtyAgKEgExBmrs(leSQVWqHidGaUSpiFhsMCyCBTQbymQnwpQzm" ascii
    $s14 = "function ooyBbrmfuZJe(ZdAudkkXkpGAF) {return isFinite(ZdAudkkXkpGAF);}" fullword ascii
    $s15 = "function DKxpViOReMXJProrS(TMEUNumpia,HwhQaksUym) {return parseInt(TMEUNumpia,HwhQaksUym);}" fullword ascii
    $s16 = "function h(MShGCHnqbnUdyC,DQRSmlPTPamVm,oLdyGflcoxT) {MShGCHnqbnUdyC[DQRSmlPTPamVm]=oLdyGflcoxT;}" fullword ascii
    $s17 = "function uhwkG(yuSfXKKvNkc,AwEQqjWuiqoDP,QuwuGveZ){Xzyh=DKxpViOReMXJProrS(yuSfXKKvNkc,AwEQqjWuiqoDP);pzpII=Xzyh.toString(QuwuGve" ascii
    $s18 = "function YhVhmMsLRUk(KwadaePtFRhgWD) {return isNaN(KwadaePtFRhgWD);}" fullword ascii
    $s19 = "Z);return pzpII;}" fullword ascii
    $s20 = "function OPGtPwJGSkAbFNQlkjFxWrFrdmLbcXzfxOKZtSKwgDQPdsEWlIrDUy(tLPvgqFfRKpDo,KmHxBNpiJeAtit){ return oUWwfkP[hbLJyElV[uhwkG(tLP" ascii

  condition:
    uint16(0) == 0x6268 and
    8 of them
}