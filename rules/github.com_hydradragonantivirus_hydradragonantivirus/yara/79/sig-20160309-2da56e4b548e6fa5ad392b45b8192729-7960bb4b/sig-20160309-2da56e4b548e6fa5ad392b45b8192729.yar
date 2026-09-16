rule sig_20160309_2da56e4b548e6fa5ad392b45b8192729 {
  meta:
    description = "datamaliciousorder - file 20160309_2da56e4b548e6fa5ad392b45b8192729.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95072ed42f3bccec886b746cd2b524cbbdff5d792abbff6c3b3d1be3f39779ab"

  strings:
    $s1  = "var jw = true  , lMEZ = qEE[7] + qEE[9] + qEE[11];" fullword ascii
    $s2  = "return SLsfrbK[0] + SLsfrbK[2] + SLsfrbK[4] + \".F\" + SLsfrbK[7] + SLsfrbK[9] + SLsfrbK[12] + SLsfrbK[14];" fullword ascii
    $s3  = "FSbor.open(wUfLw,PPxAJ,false);" fullword ascii
    $s4  = "var SLsfrbK = \"Sc McioWeE r hmsiJyHTq ipting fzufnKN PEv ile hMXLsvwfySUNlw System jX EgINs Obj pXaKIr ect XZweAEG\".split(\" " ascii
    $s5  = "var qEE = (\"2.XMLHTTP xHMAwuE rMXux XML ream St bPjRylXx AD SyNaPXY O CCmE D\").split(\" \");" fullword ascii
    $s6  = "function KaFH(DQdrG) {" fullword ascii
    $s7  = "Ftd = k; break; " fullword ascii
    $s8  = "return squaOwR(pT,JhlhB[928-922]+JhlhB[502-495]+JhlhB[854-846]);" fullword ascii
    $s9  = "return WAFkc.status;" fullword ascii
    $s10 = "function LYvg(DeYxH) {" fullword ascii
    $s11 = "return new ActiveXObject(nTwbwa);" fullword ascii
    $s12 = "function JsQzpPPK(KKK) {" fullword ascii
    $s13 = "function aoLVyLWF(FxlYR,vxJhgg) {" fullword ascii
    $s14 = "function yUdiMfnY() {" fullword ascii
    $s15 = "function tMoQ(RTdsV) {" fullword ascii
    $s16 = "if (JCQmj > 151681-619){return true;} else {return false;}" fullword ascii
    $s17 = "function pXSKNGP(Rawr) {" fullword ascii
    $s18 = "function oJqPX(nTwbwa) {" fullword ascii
    $s19 = "if(k>=J.length) {break;}" fullword ascii
    $s20 = "function NalF(sMcyu) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}