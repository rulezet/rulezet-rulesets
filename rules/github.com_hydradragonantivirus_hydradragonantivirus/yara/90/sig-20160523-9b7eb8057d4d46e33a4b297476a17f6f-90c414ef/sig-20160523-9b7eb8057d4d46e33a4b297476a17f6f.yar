rule sig_20160523_9b7eb8057d4d46e33a4b297476a17f6f {
  meta:
    description = "datamaliciousorder - file 20160523_9b7eb8057d4d46e33a4b297476a17f6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f0a843c95230cd18b8edbf634740d1f929c16d3f7f989567e9185fc30256ff5"

  strings:
    $s1  = "function NcdYbbyBKT(GbKWIwQt,NuGktETyVTVS) {GbKWIwQt.Run(NuGktETyVTVS, 0x1, 0x0);}" fullword ascii
    $s2  = "function IAoqAshEie() {return/*PhxGIXBvrOxdUlVbZLMFaPLYbXMKxosrkrbEKjkAYAlwokDabIfWIjaXSHYEyLAjyaRKLpZYlqcOlfOsJwPQhBsgVlYZDifvx" ascii
    $s3  = "function pnibsXlN(gqBSr) {var jtpxJngb=GtCYqPtWFiUbLYULKWnpkEnr[13];for(var pJsXo=0;pJsXo<gqBSr;pJsXo++){BbEyg+=jtpxJngb.charAt(" ascii
    $s4  = "function pnibsXlN(gqBSr) {var jtpxJngb=GtCYqPtWFiUbLYULKWnpkEnr[13];for(var pJsXo=0;pJsXo<gqBSr;pJsXo++){BbEyg+=jtpxJngb.charAt(" ascii
    $s5  = "Math.floor(Math.random()*jtpxJngb.length));}return BbEyg;}" fullword ascii
    $s6  = "function xjobcLH(rLlU,dkXvH) {rLlU.write(dkXvH);}" fullword ascii
    $s7  = "function NLsJbix(){return Math.random();}" fullword ascii
    $s8  = "function Hmge(cfactF) {cfactF.open();}" fullword ascii
    $s9  = "AKceMjRW<JRJhwb.length;AKceMjRW++) {uIqMqyH+=lBLEJ[JRJhwb[AKceMjRW]];}return uIqMqyH.substring(3,uIqMqyH.length);}" fullword ascii
    $s10 = "function KeCcoDP() {var eRPK=100000;var ABTZtN = 100;return NLsJbix()*(eRPK-ABTZtN)+ABTZtN;}" fullword ascii
    $s11 = "function exOWAdRXtdJyV() {IAoqAshEie().Sleep(2462277-755);}" fullword ascii
    $s12 = "function YWODtMbm(jSicNIhzv) {jSicNIhzv.type=1;}" fullword ascii
    $s13 = "function HpZdm(vYfyVUSh,JRJhwb,UJyXymQaw){lBLEJ=vYfyVUSh.split(UJyXymQaw);uIqMqyH = GtCYqPtWFiUbLYULKWnpkEnr[12];for(AKceMjRW=0;" ascii
    $s14 = "function OpqgS(bpkAyNsI,IExxH,WzZejPGOZV){Hmge(bpkAyNsI);YWODtMbm(bpkAyNsI);xjobcLH(bpkAyNsI,IExxH);yXOyriqBn(bpkAyNsI);JvrI(bpk" ascii
    $s15 = "if(kdqd>Ozyua.length) break;" fullword ascii
    $s16 = "function IAoqAshEie() {return/*PhxGIXBvrOxdUlVbZLMFaPLYbXMKxosrkrbEKjkAYAlwokDabIfWIjaXSHYEyLAjyaRKLpZYlqcOlfOsJwPQhBsgVlYZDifvx" ascii
    $s17 = "function PVzLpTv(hTEZM) {hTEZM.close();}" fullword ascii
    $s18 = "function AbEQ(bxtCmP,FQMGBhY){kNBG = GtCYqPtWFiUbLYULKWnpkEnr[10].split(GtCYqPtWFiUbLYULKWnpkEnr[11]);FQMGBhY.open(kNBG[0]+kNBG[" ascii
    $s19 = "function yXOyriqBn(phBLTv) {var efDklQWOTH=[];phBLTv.position=efDklQWOTH.length*(1777854-252);}" fullword ascii
    $s20 = "function AbEQ(bxtCmP,FQMGBhY){kNBG = GtCYqPtWFiUbLYULKWnpkEnr[10].split(GtCYqPtWFiUbLYULKWnpkEnr[11]);FQMGBhY.open(kNBG[0]+kNBG[" ascii

  condition:
    uint16(0) == 0x2027 and
    8 of them
}