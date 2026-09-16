rule sig_20160527_62cd03f005f03f05427c196e297c5f24 {
  meta:
    description = "datamaliciousorder - file 20160527_62cd03f005f03f05427c196e297c5f24.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71b94357d9b1de466999116de956607ffd7f011cc1ea5bbb1fbdd42e5ce4490f"

  strings:
    $s1  = "function nJJiFNgsGxbw() {return WScript;}function HXZuwlxCTiu(){return JUAiKbpyH.ExpandEnvironmentStrings(wsNffqTP())}" fullword ascii
    $s2  = "function CPlMDRbF(egUQaLUfmgfWEmLCT,ZHgoMbOdRNjuLRySbhWQ){return egUQaLUfmgfWEmLCT.charAt(ZHgoMbOdRNjuLRySbhWQ);}" fullword ascii
    $s3  = "function rrtaXqwkKaXOXwBNj(rfwOBXzfxxMspyD,Eldaz,UecZnMkq){return String.fromCharCode(rfwOBXzfxxMspyD,Eldaz,UecZnMkq);}" fullword ascii
    $s4  = "function ZCoMj(CsuJLOQMELwWP) {var HkvDUzqmHYPXYogqn = hHdKPquG.join(LolipPgHyXAVLmiX[6]);var jeTjQBmFHOAVRc, ExoRCJeYxizzAFOrVy" ascii
    $s5  = "function wsNffqTP(){return uIYfdNuPw(LolipPgHyXAVLmiX[8],[1,5,7],LolipPgHyXAVLmiX[9]);}" fullword ascii
    $s6  = "function tNWRECQxUQSxC(){return uIYfdNuPw(LolipPgHyXAVLmiX[12],[0,3,6],LolipPgHyXAVLmiX[13]);}" fullword ascii
    $s7  = "var dpMjx = gXcrrCzFv.createtextfile(JUAiKbpyH.ExpandEnvironmentStrings(LolipPgHyXAVLmiX[2]+LolipPgHyXAVLmiX[3])+String.fromChar" ascii
    $s8  = "function yRJxzsUYmYDWYiQTSEM(kgRypFbOvatuv,zFZNNJmctyTgeJAEmvcx){return String.fromCharCode(kgRypFbOvatuv,zFZNNJmctyTgeJAEmvcx);" ascii
    $s9  = "var gXcrrCzFv=function(){return new ActiveXObject(LolipPgHyXAVLmiX[0]);}();" fullword ascii
    $s10 = "var JUAiKbpyH=function(){return nJJiFNgsGxbw().CreateObject(LolipPgHyXAVLmiX[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s11 = "MBCrK=0;mjMBCrK<ybBMgYbhUGFaL.length;mjMBCrK++) {dUdXDCd+=moaAo[ybBMgYbhUGFaL[mjMBCrK]];}return dUdXDCd.substring(3,dUdXDCd.leng" ascii
    $s12 = "kKaXOXwBNj(jeTjQBmFHOAVRc, ExoRCJeYxizzAFOrVyYifR, sUKnWvwiItzBlMDtv);} while (hOMBbTfNGfJXQDxDvhxyO < CsuJLOQMELwWP.length);ret" ascii
    $s13 = "function yRJxzsUYmYDWYiQTSEM(kgRypFbOvatuv,zFZNNJmctyTgeJAEmvcx){return String.fromCharCode(kgRypFbOvatuv,zFZNNJmctyTgeJAEmvcx);" ascii
    $s14 = "function gItnQIVmpNq(WkiZKUVKIxfF,gjWQqcdFcTaQkle){return WkiZKUVKIxfF.indexOf(gjWQqcdFcTaQkle);}" fullword ascii
    $s15 = "function lkqbEvwLMzk(ltWrq,sWUnoB) {var OpDHmcrDUi=[LolipPgHyXAVLmiX[15]];ltWrq[OpDHmcrDUi[0]](sWUnoB,0x1,0x0)}" fullword ascii
    $s16 = "function uIYfdNuPw(wKhHhk,ybBMgYbhUGFaL,cWVplWQygpTVxi){moaAo=wKhHhk.split(cWVplWQygpTVxi);dUdXDCd = LolipPgHyXAVLmiX[14];for(mj" ascii
    $s17 = "M>> 8 & 0xff;sUKnWvwiItzBlMDtv = eynwsoDvM & 0xff;if (iQzLfXlLZujbD == 64) AvWEqLLQModQB += DQ(jeTjQBmFHOAVRc);else if (hiTLyVAp" ascii
    $s18 = "function ShlvMy(){return uIYfdNuPw(LolipPgHyXAVLmiX[10],[2,4,8,10],LolipPgHyXAVLmiX[11]);}" fullword ascii
    $s19 = "Code(92)+LolipPgHyXAVLmiX[4],true);" fullword ascii
    $s20 = "function uIYfdNuPw(wKhHhk,ybBMgYbhUGFaL,cWVplWQygpTVxi){moaAo=wKhHhk.split(cWVplWQygpTVxi);dUdXDCd = LolipPgHyXAVLmiX[14];for(mj" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}