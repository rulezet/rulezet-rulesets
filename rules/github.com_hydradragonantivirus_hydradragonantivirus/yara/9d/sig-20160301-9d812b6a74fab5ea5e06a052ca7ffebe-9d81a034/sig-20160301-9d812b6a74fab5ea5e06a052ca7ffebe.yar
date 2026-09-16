rule sig_20160301_9d812b6a74fab5ea5e06a052ca7ffebe {
  meta:
    description = "datamaliciousorder - file 20160301_9d812b6a74fab5ea5e06a052ca7ffebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94b8e25230239bc32a04aac47d5f176edf4b0ec11017f0c3589f34d1162e4dac"

  strings:
    $s1  = "var YI = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(GosfR);" fullword ascii
    $s3  = "var xHJ = (RmR + \"TTP\" + \" pNaveLv lHGYP XML ream St nLYpHLuz AD bGyWveO OD\").split(\" \");" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + OnujnjH + \".F\" + JufbZRCUti + btVlo + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var Cd = true  , fFUs = xHJ[7] + \"\" + xHJ[9];" fullword ascii
    $s6  = "wloKs.open(tDyRs,pwuYP,false);" fullword ascii
    $s7  = "function DNeticqey(pwevItWDtxj) {" fullword ascii
    $s8  = "if (SgHuB > 197819-837){return true;} else {return false;}" fullword ascii
    $s9  = "return FKUAX;" fullword ascii
    $s10 = "function XNYp(vstQB) {" fullword ascii
    $s11 = "function xcrg(wloKs,pwuYP,tDyRs) {" fullword ascii
    $s12 = "function xsHz(SgHuB) {" fullword ascii
    $s13 = "function sjAK(GkFVS,rGVja) {" fullword ascii
    $s14 = "if (((new Date())>0,7185569888)) {" fullword ascii
    $s15 = "function nqsdw(amDMIm) {" fullword ascii
    $s16 = "function bgqW(ZoMFy,EjwsY) {" fullword ascii
    $s17 = "if(C>=W.length) {break;}" fullword ascii
    $s18 = "if (rmKjH == 665-465){return true;} else {return false;}" fullword ascii
    $s19 = "return df.ExpandEnvironmentStrings(YI);" fullword ascii
    $s20 = "function PyhivZPLw(FHiqg,fUcxA,HLZdI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}