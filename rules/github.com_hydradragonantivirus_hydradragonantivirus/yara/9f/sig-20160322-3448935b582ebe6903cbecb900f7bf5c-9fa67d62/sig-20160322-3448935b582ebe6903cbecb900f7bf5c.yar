rule sig_20160322_3448935b582ebe6903cbecb900f7bf5c {
  meta:
    description = "datamaliciousorder - file 20160322_3448935b582ebe6903cbecb900f7bf5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf1ffc46facd5fff3c98bfe59022098b0479364d0f72338824d240cf7e6a54f1"

  strings:
    $s1  = "return WScript.CreateObject(DVlhU);" fullword ascii
    $s2  = "var Ta = true  , AnQq = iHl[7] + iHl[9] + iHl[11];" fullword ascii
    $s3  = "return zwKuLmD[0] + zwKuLmD[2] + zwKuLmD[4] + \".F\" + zwKuLmD[7] + zwKuLmD[9] + zwKuLmD[12] + zwKuLmD[14];" fullword ascii
    $s4  = "var zwKuLmD = ISNjA(hDePzQtpwR+\" \"+\"System CW SRpWI Obj nJuNnR ect UavtglV rDyno\", \" \");" fullword ascii
    $s5  = "CZDy.open(cilsa,Gnejb,false);" fullword ascii
    $s6  = "var iHl = (\"2.XMLHTTP qDBOZRp leGWw XML ream St IwFBoqWt AD njBevSF O raUP D\").split(\" \");" fullword ascii
    $s7  = "return ulhFBc.position=968-968;" fullword ascii
    $s8  = "function yMOhnsO(VnKj) {" fullword ascii
    $s9  = "return WbSxx.status;" fullword ascii
    $s10 = "if (zVouB == 1174-974){return true;} else {return false;}" fullword ascii
    $s11 = "function yjJz(WbSxx) {" fullword ascii
    $s12 = "function fWCj(TgHpf) {" fullword ascii
    $s13 = "function pWJo(wuSNu,yWYAa) {" fullword ascii
    $s14 = "if(F>=S.length) {break;}" fullword ascii
    $s15 = "return VnKj[UqaBgH[0]];" fullword ascii
    $s16 = "function sUcZ(OKVjQ,Gnejb,cilsa) {" fullword ascii
    $s17 = "QfS = F; break; " fullword ascii
    $s18 = "function mKxfSEFKe(fvAkuRSfCKp) {" fullword ascii
    $s19 = "return jUAE.ExpandEnvironmentStrings(uYAbK);" fullword ascii
    $s20 = "function NbaV(HxOkj,wzbIA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}