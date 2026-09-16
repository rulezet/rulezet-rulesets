rule sig_20160308_de9186323478413d874e158a1acf34ff {
  meta:
    description = "datamaliciousorder - file 20160308_de9186323478413d874e158a1acf34ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ecbb5a40c51fd9c74975b79d5302912651fa795591ed8cbe91d99bfec12a494"

  strings:
    $s1  = "var uQ = true  , wPms = fSs[7] + fSs[9] + fSs[11];" fullword ascii
    $s2  = "return DogYNLn[0] + DogYNLn[2] + DogYNLn[4] + \".F\" + DogYNLn[7] + DogYNLn[9] + DogYNLn[12] + DogYNLn[14];" fullword ascii
    $s3  = "var DogYNLn = \"Sc ThrDnbU r rvGsSyRDj ipting IyylPFv FCk ile chAbjzRFIPbnDM System ne naSMs Obj rwdNvm ect nACnJkH\".split(\" " ascii
    $s4  = "var fSs = (\"2.XMLHTTP BxyuiXs nwlKG XML ream St BhYnhnSo AD RbxPvyB O jspk D\").split(\" \");" fullword ascii
    $s5  = "XpxWO.open(RMLTm,vznSi,false);" fullword ascii
    $s6  = "function QwddSXrzQ(SRKTaiSzMRx) {" fullword ascii
    $s7  = "function kCKl(nlnIr) {" fullword ascii
    $s8  = "function vcUN(MfsnE) {" fullword ascii
    $s9  = "return ODqqB;" fullword ascii
    $s10 = "return XT.ExpandEnvironmentStrings(JSrEb[6]+JSrEb[7]+JSrEb[8]);" fullword ascii
    $s11 = "function dYfpHtSR(YiN) {" fullword ascii
    $s12 = "function FbOM(JwBAy) {" fullword ascii
    $s13 = "return zzeB.responseBody;" fullword ascii
    $s14 = "if (nlnIr > 159585-385){return true;} else {return false;}" fullword ascii
    $s15 = "ptk = p; break; " fullword ascii
    $s16 = "function Ejzj(ZiNuD,UzoMS) {" fullword ascii
    $s17 = "return rvHTj.status;" fullword ascii
    $s18 = "return new ActiveXObject(bIRQGI);" fullword ascii
    $s19 = "function xywuTwpb() {" fullword ascii
    $s20 = "if(p>=W.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}