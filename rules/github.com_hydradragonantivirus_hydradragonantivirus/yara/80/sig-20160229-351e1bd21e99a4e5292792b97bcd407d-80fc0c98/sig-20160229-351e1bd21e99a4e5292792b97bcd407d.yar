rule sig_20160229_351e1bd21e99a4e5292792b97bcd407d {
  meta:
    description = "datamaliciousorder - file 20160229_351e1bd21e99a4e5292792b97bcd407d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44181fc808bc46681a98d85a39cf451a4befb59b2ab65745bc330b08212b5868"

  strings:
    $s1  = "var Aw = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(KvhaZ);" fullword ascii
    $s3  = "var IS = true  , PCZC = nov[7] + \"\" + nov[9];" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + lWROTOn + \".F\" + oRKYZddLja + VOIrt + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var nov = (qVH + \"TTP\" + \" FSOVsgh VonhD XML ream St afuOfBbU AD ZAdZlGC OD\").split(\" \");" fullword ascii
    $s6  = "function HeQf(gSKEy) {" fullword ascii
    $s7  = "UYCwg.open(eELzW,FlPok,false);" fullword ascii
    $s8  = "if (gSKEy > 183557-854){return true;} else {return false;}" fullword ascii
    $s9  = "function aKmb(UYCwg,FlPok,eELzW) {" fullword ascii
    $s10 = "function nSVbQyVuQ(NpVlYOvWxjp) {" fullword ascii
    $s11 = "return gA.ExpandEnvironmentStrings(Aw);" fullword ascii
    $s12 = "return bgQDl;" fullword ascii
    $s13 = "if(s>=T.length) {break;}" fullword ascii
    $s14 = "function qWZn(qtwsE) {" fullword ascii
    $s15 = "function opHR(PPnTD,udCWQ) {" fullword ascii
    $s16 = "function YgPd(xcSZA) {" fullword ascii
    $s17 = "function yoOMNSLlt(xwIJD,CHbiv,FRlQE) {" fullword ascii
    $s18 = "function Tykd(KvhaZ) {" fullword ascii
    $s19 = "function acFP(GESAW) {" fullword ascii
    $s20 = "function XEYYgPgA() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}