rule sig_20160301_01cde2db2c98e9cec0c02b9342064b28 {
  meta:
    description = "datamaliciousorder - file 20160301_01cde2db2c98e9cec0c02b9342064b28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8184fdec145b7b7d9f83a1562557a3ce88ea4a0081e506ae734d271770f79fb6"

  strings:
    $s1  = "var gk = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(HIUnP);" fullword ascii
    $s3  = "var kRe = (rQj + \"TTP\" + \" RGpPjEt AOTCi XML ream St moOEEIuo AD jXZdnWu OD\").split(\" \");" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + pEFVfQB + \".F\" + sWCJEEgmjG + SUHjE + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var RN = true  , fcJR = kRe[7] + \"\" + kRe[9];" fullword ascii
    $s6  = "CJcyB.open(UfLpH,iPKWJ,false);" fullword ascii
    $s7  = "function GQXBSWoNL(pBIrG,DOkEy,vxfUx) {" fullword ascii
    $s8  = "function DSEh(fbfUv) {" fullword ascii
    $s9  = "return vJccs.status;" fullword ascii
    $s10 = "function BdyCZGth() {" fullword ascii
    $s11 = "function NVmO(MpdEF) {" fullword ascii
    $s12 = "return new ActiveXObject(pKjKzq);" fullword ascii
    $s13 = "function zvvZ(jJcBJ,ayKDE) {" fullword ascii
    $s14 = "function Mcbk(CJcyB,iPKWJ,UfLpH) {" fullword ascii
    $s15 = "if (EVvFa > 183618-680){return true;} else {return false;}" fullword ascii
    $s16 = "return CgMMO;" fullword ascii
    $s17 = "function hsGE(EVvFa) {" fullword ascii
    $s18 = "function Aifk(Ugnzd) {" fullword ascii
    $s19 = "if (((new Date())>0,7359241888)) {" fullword ascii
    $s20 = "if (MpdEF == 839-639){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}