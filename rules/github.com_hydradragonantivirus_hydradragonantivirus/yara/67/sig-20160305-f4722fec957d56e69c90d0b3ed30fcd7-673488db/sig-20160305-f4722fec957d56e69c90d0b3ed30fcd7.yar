rule sig_20160305_f4722fec957d56e69c90d0b3ed30fcd7 {
  meta:
    description = "datamaliciousorder - file 20160305_f4722fec957d56e69c90d0b3ed30fcd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "745242d60f6fca74f62522385c81d9020df0912e89cec99617d7124ac558b340"

  strings:
    $s1  = "var jKMqV = \"ICLxIZ aGr pt.Shell DljpdwU Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var Ho = true  , ZTZe = vix[7] + \"\" + vix[9];" fullword ascii
    $s3  = "var vix = (PlW + \"TTP\" + \" xbpgmbW WAvqG XML ream St zEDyaPhF AD leTuzQU OD\").split(\" \");" fullword ascii
    $s4  = "return xcFAOJs[0] + xcFAOJs[2] + xcFAOJs[4] + \".F\" + xcFAOJs[7] + xcFAOJs[9] + xcFAOJs[12] + xcFAOJs[14];" fullword ascii
    $s5  = "var xcFAOJs = \"Sc xXTTkdZ r UWAsWQSyj ipting ukEgvLx jTF ile fDICrfpkHqBaxd System Xb wFDID Obj zCubmQ ect khraJUb\".split(\" " ascii
    $s6  = "function RkYF(AbtDc,yMvpA) {" fullword ascii
    $s7  = "return aQ.ExpandEnvironmentStrings(jKMqV[6]);" fullword ascii
    $s8  = "return acKNTdg" fullword ascii
    $s9  = "if(w>=R.length) {break;}" fullword ascii
    $s10 = "function fSJnYdh(USnP) {" fullword ascii
    $s11 = "function PTCpNaRu() {" fullword ascii
    $s12 = "if (kpTod > 186587-410){return true;} else {return false;}" fullword ascii
    $s13 = "function IOYa(cfIyl) {" fullword ascii
    $s14 = "function RFog(YKQDx) {" fullword ascii
    $s15 = "if (((new Date())>0,7858645888)) {" fullword ascii
    $s16 = "function aStXwcgFh(yCeZdbqcjRN) {" fullword ascii
    $s17 = "function BhtvIQUVp(zgDbb,XOSit,FhTZn) {" fullword ascii
    $s18 = "function umAU(FQNWI) {" fullword ascii
    $s19 = "bAS = w; break; " fullword ascii
    $s20 = "function dXCi(SjFVK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}