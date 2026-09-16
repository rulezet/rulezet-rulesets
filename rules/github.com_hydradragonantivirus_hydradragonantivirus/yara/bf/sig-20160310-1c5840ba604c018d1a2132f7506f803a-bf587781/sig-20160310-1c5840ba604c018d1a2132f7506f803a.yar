rule sig_20160310_1c5840ba604c018d1a2132f7506f803a {
  meta:
    description = "datamaliciousorder - file 20160310_1c5840ba604c018d1a2132f7506f803a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59a36475105d91d34447248c26414e9fbcb3742d65dc28ff631dc601365bb1fd"

  strings:
    $s1  = "function tYGKHirCy(thmViPJdgSH) {" fullword ascii
    $s2  = "return ahieWvN[0] + ahieWvN[2] + ahieWvN[4] + \".F\" + ahieWvN[7] + ahieWvN[9] + ahieWvN[12] + ahieWvN[14];" fullword ascii
    $s3  = "var ZV = true  , hFPp = tDt[7] + tDt[9] + tDt[11];" fullword ascii
    $s4  = "BUrNm.open(YeUar,KWkCz,false);" fullword ascii
    $s5  = "var tDt = (\"2.XMLHTTP CrAtYdw XrNdU XML ream St czFQzfuF AD HdRVpwt O DwCF D\").split(\" \");" fullword ascii
    $s6  = "var ahieWvN = \"Sc GYrPiTw r CPaYHiLjH ipting fnztEhV FfR ile FNolfmDJGzzosD System NR KoxrC Obj CvOMjE ect wyRcXZX\".split(\" " ascii
    $s7  = "function jVON(fCfDh) {" fullword ascii
    $s8  = "function MBTh(SjWHO) {" fullword ascii
    $s9  = "return rViB.responseBody;" fullword ascii
    $s10 = "function rjICe(PEjOIM) {" fullword ascii
    $s11 = "function urNBnHapj(eKkeH,eDzJB,pgABf,JOfu) {" fullword ascii
    $s12 = "if (oHjzS == 481-281){return true;} else {return false;}" fullword ascii
    $s13 = "if (z >= fCfDh.length) {break;}" fullword ascii
    $s14 = "return PEjOIM.position=356-356;" fullword ascii
    $s15 = "eYZ = b; break; " fullword ascii
    $s16 = "function HCJqpciY(ERP) {" fullword ascii
    $s17 = "function WIjB(tFSpj) {" fullword ascii
    $s18 = "return new ActiveXObject(MZePIr);" fullword ascii
    $s19 = "function sOZgnzKr(ZOptb,AclriA) {" fullword ascii
    $s20 = "function LvYW(aDotH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}