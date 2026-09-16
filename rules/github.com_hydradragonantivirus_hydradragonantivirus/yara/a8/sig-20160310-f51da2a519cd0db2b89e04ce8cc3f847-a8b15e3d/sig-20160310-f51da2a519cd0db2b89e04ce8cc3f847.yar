rule sig_20160310_f51da2a519cd0db2b89e04ce8cc3f847 {
  meta:
    description = "datamaliciousorder - file 20160310_f51da2a519cd0db2b89e04ce8cc3f847.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65da95ce3855f4bc334a3bd98b3d43a54d1a681950a2933e6a3c93c8bfb125a4"

  strings:
    $s1  = "return OInMaUZ[0] + OInMaUZ[2] + OInMaUZ[4] + \".F\" + OInMaUZ[7] + OInMaUZ[9] + OInMaUZ[12] + OInMaUZ[14];" fullword ascii
    $s2  = "var ez = true  , EBxH = oWa[7] + oWa[9] + oWa[11];" fullword ascii
    $s3  = "var oWa = (\"2.XMLHTTP yeQDZBy uVsNF XML ream St nhlLfzvf AD mJObNpv O mPkP D\").split(\" \");" fullword ascii
    $s4  = "TIoCZ.open(rsoHi,NNuHM,false);" fullword ascii
    $s5  = "var OInMaUZ = \"Sc dDHRepd r ZKidHlNgh ipting JfdasCX izy ile GyFHnzJQqnrhLt System Di FFbhb Obj OxYKfb ect WzrIrbv\".split(\" " ascii
    $s6  = "function NrSik(RxDZHK) {" fullword ascii
    $s7  = "function pClu(wFmFR) {" fullword ascii
    $s8  = "if (d >= fgkrl.length) {break;}" fullword ascii
    $s9  = "return mWMLK;" fullword ascii
    $s10 = "function dHpNYpQq(CwB) {" fullword ascii
    $s11 = "if(n>=f.length) {break;}" fullword ascii
    $s12 = "return PDowFee" fullword ascii
    $s13 = "function GwhipKxS(BGmxH,dSSFKb) {" fullword ascii
    $s14 = "return new ActiveXObject(hgJnPF);" fullword ascii
    $s15 = "if (AijBS > 180140-838){return true;} else {return false;}" fullword ascii
    $s16 = "KnH = n; break; " fullword ascii
    $s17 = "if (wFmFR == 617-417){return true;} else {return false;}" fullword ascii
    $s18 = "function HLUskUO(Mcck) {" fullword ascii
    $s19 = "return sLCB.ExpandEnvironmentStrings(inubA);" fullword ascii
    $s20 = "function KVUwhvN(sLCB,inubA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}