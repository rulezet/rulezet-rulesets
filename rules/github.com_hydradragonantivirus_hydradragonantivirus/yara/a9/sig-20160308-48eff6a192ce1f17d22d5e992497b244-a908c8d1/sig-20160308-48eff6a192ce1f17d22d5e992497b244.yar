rule sig_20160308_48eff6a192ce1f17d22d5e992497b244 {
  meta:
    description = "datamaliciousorder - file 20160308_48eff6a192ce1f17d22d5e992497b244.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd1e2d4f42750dfb56b1dee3491e14e9f83cbdba251cd99c0c1cda8f3bcf0c48"

  strings:
    $s1  = "var Fl = true  , SAtY = iIB[7] + iIB[9] + iIB[11];" fullword ascii
    $s2  = "return hhMXlAF[0] + hhMXlAF[2] + hhMXlAF[4] + \".F\" + hhMXlAF[7] + hhMXlAF[9] + hhMXlAF[12] + hhMXlAF[14];" fullword ascii
    $s3  = "QLDJZ.open(pNXnh,CsoTF,false);" fullword ascii
    $s4  = "var hhMXlAF = \"Sc vdBAiLo r VqkXVrIRF ipting JoAJrhX Pfd ile vASGBJjuuQcmjI System An kUhmM Obj oJEyKX ect blVIFzm\".split(\" " ascii
    $s5  = "var iIB = (\"2.XMLHTTP iucGfiC VkGOK XML ream St AXOJykBj AD rUmugFZ O GmKn D\").split(\" \");" fullword ascii
    $s6  = "if (kTBXQ == 346-146){return true;} else {return false;}" fullword ascii
    $s7  = "return ob.ExpandEnvironmentStrings(rqMlO[6]+rqMlO[7]+rqMlO[8]);" fullword ascii
    $s8  = "function Oguq(QLDJZ,CsoTF,pNXnh) {" fullword ascii
    $s9  = "if (uBiab > 156453-297){return true;} else {return false;}" fullword ascii
    $s10 = "function tBjJ(kTBXQ) {" fullword ascii
    $s11 = "if (H >= dHsFd.length) {break;}" fullword ascii
    $s12 = "if(M>=S.length) {break;}" fullword ascii
    $s13 = "return new ActiveXObject(XeJECT);" fullword ascii
    $s14 = "return HfgQbGH" fullword ascii
    $s15 = "function TDOhbZW(YSXJ) {" fullword ascii
    $s16 = "function moxll(XeJECT) {" fullword ascii
    $s17 = "function dRyWtDfG(FQg) {" fullword ascii
    $s18 = "function NtrF(bjRdJ) {" fullword ascii
    $s19 = "return FQg.size;" fullword ascii
    $s20 = "var xFGiftyb = \"FEIs Ws WppsGXD cri pt.S suYeGD hell\".split(\" \");" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}