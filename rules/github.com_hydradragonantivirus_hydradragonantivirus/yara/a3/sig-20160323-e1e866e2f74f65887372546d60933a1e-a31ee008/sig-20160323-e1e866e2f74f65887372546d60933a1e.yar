rule sig_20160323_e1e866e2f74f65887372546d60933a1e {
  meta:
    description = "datamaliciousorder - file 20160323_e1e866e2f74f65887372546d60933a1e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "451ff487d2cf4a86fca9b6c0ec7b8877a522208d18c325992e70d4b4af36e7f2"

  strings:
    $s1  = "return WScript.CreateObject(QgBxy);" fullword ascii
    $s2  = "var Qz = true  , Wcsa = RoD[7] + RoD[9] + RoD[11];" fullword ascii
    $s3  = "return tQiWypO[0] + tQiWypO[2] + tQiWypO[4] + \".F\" + tQiWypO[7] + tQiWypO[9] + tQiWypO[12] + tQiWypO[14];" fullword ascii
    $s4  = "EhMK.open(fjrcT,ZZsQu,false);" fullword ascii
    $s5  = "var tQiWypO = YBwTk(ZJgTSDcJnr+\" \"+\"System HD HyEwV Obj ecloIz ect GjUCfyO HqTKH\", \" \");" fullword ascii
    $s6  = "var RoD = (\"2.XMLHTTP krkxWUW iTybe XML ream St VJuhTyoF AD penzBxA O JjFt D\").split(\" \");" fullword ascii
    $s7  = "if(E>=y.length) {break;}" fullword ascii
    $s8  = "if (i >= kuiLt.length) {break;}" fullword ascii
    $s9  = "function twRU(Abymd) {" fullword ascii
    $s10 = "return jrdmh;" fullword ascii
    $s11 = "function UjFoH(lzSnhO) {" fullword ascii
    $s12 = "function Zqhs(RTsEd) {" fullword ascii
    $s13 = "return AAjT.ExpandEnvironmentStrings(MqEZs);" fullword ascii
    $s14 = "function luYqwOKx(Usp) {" fullword ascii
    $s15 = "return kQc.split(PCRpB);" fullword ascii
    $s16 = "function CNJX(kuiLt) {" fullword ascii
    $s17 = "function jiJUOAV(akIq) {" fullword ascii
    $s18 = "if (wxzRE == 474-274){return true;} else {return false;}" fullword ascii
    $s19 = "return akIq[USQwBT[0]];" fullword ascii
    $s20 = "function JvFnO(LjORuj) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}