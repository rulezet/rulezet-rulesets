rule sig_20160303_e90b12095153792eb9ee1a6e6c169ab8 {
  meta:
    description = "datamaliciousorder - file 20160303_e90b12095153792eb9ee1a6e6c169ab8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aaded2424c1e5825f9803fbe5df104b1c548487b0d3f42cd714e0bbb7ae7d498"

  strings:
    $s1  = "var YW = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(FpJvr);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + qygosgv + \".F\" + RaBhnngAjZ + DdPQS + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var kZJ = (NjH + \"TTP\" + \" JoZoMjx aFzDh XML ream St wNfWOZBc AD QDoBGhx OD\").split(\" \");" fullword ascii
    $s5  = "var Uf = true  , wfYX = kZJ[7] + \"\" + kZJ[9];" fullword ascii
    $s6  = "rRIQj.open(HfsWh,QuKQe,false);" fullword ascii
    $s7  = "function KwgTgonbJ(jWARI,rWEZt,KHicC) {" fullword ascii
    $s8  = "return Iv.ExpandEnvironmentStrings(YW);" fullword ascii
    $s9  = "function DNciC(YYuYkB) {" fullword ascii
    $s10 = "return gexwi;" fullword ascii
    $s11 = "function Ekni(rvtDl) {" fullword ascii
    $s12 = "return new ActiveXObject(YYuYkB);" fullword ascii
    $s13 = "function wfUm(hGqwW) {" fullword ascii
    $s14 = "function usbK(ZAxSo) {" fullword ascii
    $s15 = "function dupE(rRIQj,QuKQe,HfsWh) {" fullword ascii
    $s16 = "if (lhhMp > 193534-153){return true;} else {return false;}" fullword ascii
    $s17 = "if (hGqwW == 1124-924){return true;} else {return false;}" fullword ascii
    $s18 = "function sZrr(FwgFU,UrAOT) {" fullword ascii
    $s19 = "function SCKj(lhhMp) {" fullword ascii
    $s20 = "if(W>=U.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}