rule sig_20160303_2cfd25e14bd20f9053fd83a1c9c50a87 {
  meta:
    description = "datamaliciousorder - file 20160303_2cfd25e14bd20f9053fd83a1c9c50a87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c33cdb18adfba588c6ad62fc1620f16d6a918afbfdb3c3f77a4c9256db5128f3"

  strings:
    $s1  = "var Tr = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(JwRjk);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + EVhLPXI + \".F\" + FmmjiyfvLM + szPmZ + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var PT = true  , OsTM = wvN[7] + \"\" + wvN[9];" fullword ascii
    $s5  = "var wvN = (FcA + \"TTP\" + \" ubIvVyh QlYNO XML ream St DbtUoogq AD qFssIoj OD\").split(\" \");" fullword ascii
    $s6  = "function EAiInbRvw(EzQATGxuamP) {" fullword ascii
    $s7  = "function BMUS(JwRjk) {" fullword ascii
    $s8  = "function zgMG(HyisQ) {" fullword ascii
    $s9  = "return new ActiveXObject(cYWHBH);" fullword ascii
    $s10 = "if (nUGXM > 177759-371){return true;} else {return false;}" fullword ascii
    $s11 = "function cWOtS(cYWHBH) {" fullword ascii
    $s12 = "function nyGg(xrHOO,CpajQ) {" fullword ascii
    $s13 = "return JiTfv;" fullword ascii
    $s14 = "function sgyu(nUGXM) {" fullword ascii
    $s15 = "function hIIy(ORSmp,mYzlG) {" fullword ascii
    $s16 = "function oSjN(VShoj) {" fullword ascii
    $s17 = "function EFOwWRej() {" fullword ascii
    $s18 = "if(s>=m.length) {break;}" fullword ascii
    $s19 = "return hs.ExpandEnvironmentStrings(Tr);" fullword ascii
    $s20 = "function fCpg(KFrWK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}