rule sig_20160311_b582af099b963a2d2cc79389a5dcffab {
  meta:
    description = "datamaliciousorder - file 20160311_b582af099b963a2d2cc79389a5dcffab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d9148eb94e3a0d389331789d4be179b703d947ba7542500936de4282f5b928f"

  strings:
    $s1  = "function LDpZ(OSPyK) {" fullword ascii
    $s2  = "var Vf = true  , DULt = oNb[7] + oNb[9] + oNb[11];" fullword ascii
    $s3  = "var yka = LDpZ(DULt + \"B.\" + oNb[5]+(892272, oNb[4]));" fullword ascii
    $s4  = "return cbfMLXS[0] + cbfMLXS[2] + cbfMLXS[4] + \".F\" + cbfMLXS[7] + cbfMLXS[9] + cbfMLXS[12] + cbfMLXS[14];" fullword ascii
    $s5  = "function vsDSwYfjg(GTZlVfeztMp) {" fullword ascii
    $s6  = "var cbfMLXS = \"Sc mgtZGcX r IDwZTXHFz ipting wBSEdOr Nio ile swYFMbOtSKnNWI System Af GnFLM Obj IpKNDt ect fxfBomz\".split(\" " ascii
    $s7  = "var oNb = (\"2.XMLHTTP vXzWwUL gtrqZ XML ream St QDeiGkSo AD JLrtSlL O NvEG D\").split(\" \");" fullword ascii
    $s8  = "CxJjP.open(gdMmZ,gllxu,false);" fullword ascii
    $s9  = "if(Q>=y.length) {break;}" fullword ascii
    $s10 = "if (ZyQQf == 379-179){return true;} else {return false;}" fullword ascii
    $s11 = "function hYLnkuov(Ayarn,aQWzoy) {" fullword ascii
    $s12 = "return JMJwe.status;" fullword ascii
    $s13 = "Nte = Q; break; " fullword ascii
    $s14 = "return KdM.size;" fullword ascii
    $s15 = "function UywLT(Wnyxwl) {" fullword ascii
    $s16 = "return new ActiveXObject(Wnyxwl);" fullword ascii
    $s17 = "return vctFZUA" fullword ascii
    $s18 = "return LVWwBbN(Dv,IZlvr[368-362]+IZlvr[457-450]+IZlvr[130-122]);" fullword ascii
    $s19 = "function HnEVTaD(OWhQ) {" fullword ascii
    $s20 = "function eTCL(ZyQQf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}