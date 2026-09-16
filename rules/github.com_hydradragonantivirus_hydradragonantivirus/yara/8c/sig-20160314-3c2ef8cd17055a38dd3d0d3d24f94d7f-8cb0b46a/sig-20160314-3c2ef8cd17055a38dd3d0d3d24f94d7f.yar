rule sig_20160314_3c2ef8cd17055a38dd3d0d3d24f94d7f {
  meta:
    description = "datamaliciousorder - file 20160314_3c2ef8cd17055a38dd3d0d3d24f94d7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e79e6bdcf087b0f274c6c9dda1331fcb5178b0fa7876b9dc7f386153cee8a197"

  strings:
    $s1  = "return VhHUfjI[0] + VhHUfjI[2] + VhHUfjI[4] + \".F\" + VhHUfjI[7] + VhHUfjI[9] + VhHUfjI[12] + VhHUfjI[14];" fullword ascii
    $s2  = "var gV = true  , aWjR = Qea[7] + Qea[9] + Qea[11];" fullword ascii
    $s3  = "rDhxA.open(czOEk,JOrrp,false);" fullword ascii
    $s4  = "var Qea = (\"2.XMLHTTP XhgtQZk soqql XML ream St vutIBQNG AD dIyVJzM O AFtB D\").split(\" \");" fullword ascii
    $s5  = "return puGXzyZ(Dj,Klzyb[681-675]+Klzyb[949-942]+Klzyb[841-833]);" fullword ascii
    $s6  = "return RjOMAXy" fullword ascii
    $s7  = "return AxELq.status;" fullword ascii
    $s8  = "function RKqJ(rDhxA,JOrrp,czOEk) {" fullword ascii
    $s9  = "if (WWNOe > 199531-489){return true;} else {return false;}" fullword ascii
    $s10 = "function tSLZ(YgoDc,wKCJO) {" fullword ascii
    $s11 = "function TQDS(iMZkN) {" fullword ascii
    $s12 = "function puGXzyZ(Kikx,hDmKl) {" fullword ascii
    $s13 = "return aYF.size;" fullword ascii
    $s14 = "tMB = U; break; " fullword ascii
    $s15 = "function wTdUS(erudmK) {" fullword ascii
    $s16 = "function JrwAhwfFA() {" fullword ascii
    $s17 = "return oAxDvJ.position=765-765;" fullword ascii
    $s18 = "function CxSk(oyNxe) {" fullword ascii
    $s19 = "return Kikx.ExpandEnvironmentStrings(hDmKl);" fullword ascii
    $s20 = "if(U>=P.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}