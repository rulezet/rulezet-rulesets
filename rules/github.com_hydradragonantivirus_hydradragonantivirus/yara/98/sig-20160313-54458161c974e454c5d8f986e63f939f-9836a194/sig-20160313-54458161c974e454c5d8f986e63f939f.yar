rule sig_20160313_54458161c974e454c5d8f986e63f939f {
  meta:
    description = "datamaliciousorder - file 20160313_54458161c974e454c5d8f986e63f939f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40698607ca1142c5fe306edeff1dc434d45024910f81130a64064cc49e5aa956"

  strings:
    $s1  = "var cT = true  , chKh = qLj[7] + qLj[9] + qLj[11];" fullword ascii
    $s2  = "return vAImSHw[0] + vAImSHw[2] + vAImSHw[4] + \".F\" + vAImSHw[7] + vAImSHw[9] + vAImSHw[12] + vAImSHw[14];" fullword ascii
    $s3  = "var vAImSHw = \"Sc WvAScHX r wvfKCNgDH ipting cWjrTza ZXf ile YAOPlrQDRzCKEB System Ct DCVId Obj IwbBFE ect DCyVfgp\".split(\" " ascii
    $s4  = "var qLj = (\"2.XMLHTTP JXWuNfo TbMAE XML ream St rWSJMPLz AD FuhOTOt O MyqL D\").split(\" \");" fullword ascii
    $s5  = "lHdTA.open(gTCff,cJTcG,false);" fullword ascii
    $s6  = "function mpEk(QwhaS,geIyc) {" fullword ascii
    $s7  = "function ipbA(eMlsJ) {" fullword ascii
    $s8  = "function MmZfNVs(eTxG) {" fullword ascii
    $s9  = "return OMWxm;" fullword ascii
    $s10 = "function VGJf(eRTYh) {" fullword ascii
    $s11 = "return rDzb.ExpandEnvironmentStrings(UUeun);" fullword ascii
    $s12 = "return UYa.size;" fullword ascii
    $s13 = "function FoHN(fuaRJ) {" fullword ascii
    $s14 = "return JePKav.position=954-954;" fullword ascii
    $s15 = "function Bczmm(JePKav) {" fullword ascii
    $s16 = "function vPsTEtot() {" fullword ascii
    $s17 = "function oRlesNalZ() {" fullword ascii
    $s18 = "function xtHXBpWEz(cDHiUWmqbKe) {" fullword ascii
    $s19 = "function fTUB(VLRTR,yuuOc) {" fullword ascii
    $s20 = "if (hMYTQ == 699-499){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}