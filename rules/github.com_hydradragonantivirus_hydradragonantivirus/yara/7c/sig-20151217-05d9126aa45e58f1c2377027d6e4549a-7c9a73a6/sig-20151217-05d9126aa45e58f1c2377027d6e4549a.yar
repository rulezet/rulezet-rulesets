rule sig_20151217_05d9126aa45e58f1c2377027d6e4549a {
  meta:
    description = "datamaliciousorder - file 20151217_05d9126aa45e58f1c2377027d6e4549a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35841a57bc7cf4a49ec8438babe7308b1e29736e479438a1ee9053ef2f602bb6"

  strings:
    $s1  = ") - 1));while(true){if (AAwHTlgcwqL >= (2765+919)/614){break;}MFoMnTGWh[AAwHTlgcwqL]=Math.round((Math.pow(Math.sin(450), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(450), 2) - 1)); while(true) { if(MFoMnTGWh[AAwHTlgcwqL] > ERBoT[AAwHTlgcwqL].length-(768+186)/954) { break; } if" ascii
    $s3  = "ow(Math.cos(388), 2) - 1)));} MFoMnTGWh[AAwHTlgcwqL]++;}AAwHTlgcwqL++;} return tqVyYzDKVtZ}" fullword ascii
    $s4  = "function SLimfXtictVgOndYL(ERBoT){tqVyYzDKVtZ= '';AAwHTlgcwqL=Math.round((Math.pow(Math.sin(757), 2) + Math.pow(Math.cos(757), 2" ascii
    $s5  = "function SLimfXtictVgOndYL(ERBoT){tqVyYzDKVtZ= '';AAwHTlgcwqL=Math.round((Math.pow(Math.sin(757), 2) + Math.pow(Math.cos(757), 2" ascii
    $s6  = "function pnuWjPq(EehDoNHSLZvODbqqSmuOBHPzPxGTeGGbEUMT) {return !KthawImMmpw(qTTbkIwGNLYtwrb(EehDoNHSLZvODbqqSmuOBHPzPxGTeGGbEUMT" ascii
    $s7  = "var Q = new Array();Q[0]=[];Q[0][0]='d';Q[0][1]='a';Q[0][2]='d';Q[0][3]='a';Q[0][4]='46';Q[0][5]='3d';Q[0][6]='42';Q[0][7]='14';" ascii
    $s8  = "function v(PuDQPpYhQYAF,kvbJNbiKzCduiZ){PuDQPpYhQYAF.push(kvbJNbiKzCduiZ);}" fullword ascii
    $s9  = "u);return ZffEY;}" fullword ascii
    $s10 = "var Q = new Array();Q[0]=[];Q[0][0]='d';Q[0][1]='a';Q[0][2]='d';Q[0][3]='a';Q[0][4]='46';Q[0][5]='3d';Q[0][6]='42';Q[0][7]='14';" ascii
    $s11 = "function KthawImMmpw(yGsoNLxFBmGNib) {return isNaN(yGsoNLxFBmGNib);}" fullword ascii
    $s12 = "function gwiHeCfPaNBrYUHFs(oGPGcuxWaw,ETajuXkVbq) {return parseInt(oGPGcuxWaw,ETajuXkVbq);}" fullword ascii
    $s13 = "function fBoAV(miMpZvRyGmA,TfFvOdVSLwnUm,TUtIYmMu){KLEA=gwiHeCfPaNBrYUHFs(miMpZvRyGmA,TfFvOdVSLwnUm);ZffEY=KLEA.toString(TUtIYmM" ascii
    $s14 = ",'e','s','V','a','W','J','R','N','g','g','q','X','*','/','Y','k','n',')','H','U','E','#','d','Z','.','[','p','4','C','N',String." ascii
    $s15 = "function EnaUojtwbHQwAYHwkXVEnlMKTZFZddyKxwZOFDKBpTZMCtClZOroJB(boDCSFxiWsain,apidriUmTXVYSL){ return AJIMkQF[DaWBYdym[fBoAV(boD" ascii
    $s16 = "function qTTbkIwGNLYtwrb(LjKbfiehpOpSviRJhCC) {return parseFloat(LjKbfiehpOpSviRJhCC);}" fullword ascii
    $s17 = "function pnuWjPq(EehDoNHSLZvODbqqSmuOBHPzPxGTeGGbEUMT) {return !KthawImMmpw(qTTbkIwGNLYtwrb(EehDoNHSLZvODbqqSmuOBHPzPxGTeGGbEUMT" ascii
    $s18 = "function EnaUojtwbHQwAYHwkXVEnlMKTZFZddyKxwZOFDKBpTZMCtClZOroJB(boDCSFxiWsain,apidriUmTXVYSL){ return AJIMkQF[DaWBYdym[fBoAV(boD" ascii
    $s19 = "function a(wHYVCOtazeUWnf,jBSFuDLgLzhlW,DnMnnncljUM) {wHYVCOtazeUWnf[jBSFuDLgLzhlW]=DnMnnncljUM;}" fullword ascii
    $s20 = "function fBoAV(miMpZvRyGmA,TfFvOdVSLwnUm,TUtIYmMu){KLEA=gwiHeCfPaNBrYUHFs(miMpZvRyGmA,TfFvOdVSLwnUm);ZffEY=KLEA.toString(TUtIYmM" ascii

  condition:
    uint16(0) == 0x6144 and
    8 of them
}