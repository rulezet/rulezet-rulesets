rule sig_20160312_79df42772670c09f027dc2422799f6fa {
  meta:
    description = "datamaliciousorder - file 20160312_79df42772670c09f027dc2422799f6fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "300ac80f2dac7da2c836d5b0d1fc5336feeb3db03edff3344b29dea17b1f90cf"

  strings:
    $s1  = "var xd = true  , AfQM = ftV[7] + ftV[9] + ftV[11];" fullword ascii
    $s2  = "return OCseJrR[0] + OCseJrR[2] + OCseJrR[4] + \".F\" + OCseJrR[7] + OCseJrR[9] + OCseJrR[12] + OCseJrR[14];" fullword ascii
    $s3  = "var OCseJrR = \"Sc ZATbgLo r ZfyiqWoUL ipting FZIUabZ zQO ile yNPPHtBdUvCgvc System xE bWJjJ Obj YByOrm ect mZmCxHN\".split(\" " ascii
    $s4  = "htZtF.open(Klrib,iaOiw,false);" fullword ascii
    $s5  = "var ftV = (\"2.XMLHTTP iPaRbXS eaNwM XML ream St aNXkjLRn AD wRBwpDJ O RIoK D\").split(\" \");" fullword ascii
    $s6  = "function BRzu(IbUna) {" fullword ascii
    $s7  = "if (r >= kaDFX.length) {break;}" fullword ascii
    $s8  = "return kmC.size;" fullword ascii
    $s9  = "return ZQaeE.status;" fullword ascii
    $s10 = "function OPzDguiwy() {" fullword ascii
    $s11 = "return lDPB.responseBody;" fullword ascii
    $s12 = "return ZSjAWPe(Eu,jDdBf[579-573]+jDdBf[220-213]+jDdBf[232-224]);" fullword ascii
    $s13 = "function nRNWOXgk() {" fullword ascii
    $s14 = "if(S>=H.length) {break;}" fullword ascii
    $s15 = "return lPKAI;" fullword ascii
    $s16 = "function ksKC(htZtF,iaOiw,Klrib) {" fullword ascii
    $s17 = "CuA = S; break; " fullword ascii
    $s18 = "if (dDRGi > 139106-923){return true;} else {return false;}" fullword ascii
    $s19 = "if (IbUna == 323-123){return true;} else {return false;}" fullword ascii
    $s20 = "function Txjq(dfnqY,GempO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}