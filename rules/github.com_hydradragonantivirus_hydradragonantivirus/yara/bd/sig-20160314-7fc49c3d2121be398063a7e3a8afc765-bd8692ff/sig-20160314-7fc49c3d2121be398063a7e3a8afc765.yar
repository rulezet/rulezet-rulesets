rule sig_20160314_7fc49c3d2121be398063a7e3a8afc765 {
  meta:
    description = "datamaliciousorder - file 20160314_7fc49c3d2121be398063a7e3a8afc765.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a4a289e9e603677332fd5841df58becc504444a7eb47c1cc7c3316ded6cca1b"

  strings:
    $s1  = "return NaVYJQy[0] + NaVYJQy[2] + NaVYJQy[4] + \".F\" + NaVYJQy[7] + NaVYJQy[9] + NaVYJQy[12] + NaVYJQy[14];" fullword ascii
    $s2  = "var cX = true  , MMOR = glj[7] + glj[9] + glj[11];" fullword ascii
    $s3  = "IPcZz.open(OTRDb,uYwLz,false);" fullword ascii
    $s4  = "var NaVYJQy = \"Sc fxHoTIM r qdgrfHGRs ipting Xkqfajo ENP ile gbpsKhawKMmrNh System Ta xIsOv Obj cjqGWR ect JlzRrKc nSVTe\".spli" ascii
    $s5  = "var NaVYJQy = \"Sc fxHoTIM r qdgrfHGRs ipting Xkqfajo ENP ile gbpsKhawKMmrNh System Ta xIsOv Obj cjqGWR ect JlzRrKc nSVTe\".spli" ascii
    $s6  = "var glj = (\"2.XMLHTTP jnsmgUu WxggH XML ream St vdSPQxyb AD GoHVPkJ O ffqv D\").split(\" \");" fullword ascii
    $s7  = "function YAKV(FbnXW,viqao) {" fullword ascii
    $s8  = "function kvrfc(oDXPBj) {" fullword ascii
    $s9  = "function dxIGv(iHUCzd) {" fullword ascii
    $s10 = "return qbPSfcz(hf,AZDzB[818-812]+AZDzB[343-336]+AZDzB[740-732]);" fullword ascii
    $s11 = "function UaRO(Aqkxp) {" fullword ascii
    $s12 = "function dUTsfxxsy(mcszYpgqXkb) {" fullword ascii
    $s13 = "function sgbi(vLjDW,gHymp) {" fullword ascii
    $s14 = "return new ActiveXObject(oDXPBj);" fullword ascii
    $s15 = "return DOL.size;" fullword ascii
    $s16 = "return LzTqM.status;" fullword ascii
    $s17 = "function rPWXhJTsc() {" fullword ascii
    $s18 = "return LWdw.ExpandEnvironmentStrings(qWitD);" fullword ascii
    $s19 = "if (CXTPY > 158062-536){return true;} else {return false;}" fullword ascii
    $s20 = "IWl = K; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}