rule sig_20160313_c5b14267f1f055c5c73ef20be22aaf97 {
  meta:
    description = "datamaliciousorder - file 20160313_c5b14267f1f055c5c73ef20be22aaf97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e23d7189ee74d563d849d42dc796fb05d2fbe1eaf429daa570197d4dfc5066a2"

  strings:
    $s1  = "var MrB = (\"2.XMLHTTP qyBRUNs AAWfC XML ream St jBSjzzVt AD qnoFmFR O znBW D\").split(\" \");" fullword ascii
    $s2  = "return VyjEgQN[0] + VyjEgQN[2] + VyjEgQN[4] + \".F\" + VyjEgQN[7] + VyjEgQN[9] + VyjEgQN[12] + VyjEgQN[14];" fullword ascii
    $s3  = "var XK = true  , Pinp = MrB[7] + MrB[9] + MrB[11];" fullword ascii
    $s4  = "var VyjEgQN = \"Sc oPFWawe r iStyxzHlt ipting HdmDRoB UEp ile aaYKOOxFGTCDbQ System iK xnGVp Obj wLKZIZ ect uWTOrOR\".split(\" " ascii
    $s5  = "zdgDU.open(wlCgD,PCcjZ,false);" fullword ascii
    $s6  = "if(Y>=c.length) {break;}" fullword ascii
    $s7  = "function gTFA(MOBnZ) {" fullword ascii
    $s8  = "function hmlQgltrm(RPdraSpFEdm) {" fullword ascii
    $s9  = "function lvAt(lZxtF) {" fullword ascii
    $s10 = "return JOWoN.status;" fullword ascii
    $s11 = "if (MOBnZ > 173923-802){return true;} else {return false;}" fullword ascii
    $s12 = "function ZwFelIWS() {" fullword ascii
    $s13 = "return tjE.size;" fullword ascii
    $s14 = "if (W >= ZlWkc.length) {break;}" fullword ascii
    $s15 = "function qWfw(JOWoN) {" fullword ascii
    $s16 = "return Xlrq.responseBody;" fullword ascii
    $s17 = "function zSURLAJO(tjE) {" fullword ascii
    $s18 = "ypa = Y; break; " fullword ascii
    $s19 = "function PWflq(tyJeUI) {" fullword ascii
    $s20 = "return QWAKLx.position=637-637;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}