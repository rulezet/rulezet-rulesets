rule sig_20160315_fed048057fedd910dc8e343d48b0a767 {
  meta:
    description = "datamaliciousorder - file 20160315_fed048057fedd910dc8e343d48b0a767.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27b26bf322c6d0acbd0a77b79fe1b373e9ebd32ae1754b1d9e6159cd0ed703e8"

  strings:
    $s1  = "return dntwXaL[0] + dntwXaL[2] + dntwXaL[4] + \".F\" + dntwXaL[7] + dntwXaL[9] + dntwXaL[12] + dntwXaL[14];" fullword ascii
    $s2  = "var Nh = true  , DEgT = jSb[7] + jSb[9] + jSb[11];" fullword ascii
    $s3  = "var dntwXaL = VZFIa(\"Sc JrANNWo r NVVilGlKH ipting xrxkdAF Ufa ile ZMEtZhkqtyiCFr System hX GrKHI Obj KOghNb ect dgNefuH HbKBM" ascii
    $s4  = "var dntwXaL = VZFIa(\"Sc JrANNWo r NVVilGlKH ipting xrxkdAF Ufa ile ZMEtZhkqtyiCFr System hX GrKHI Obj KOghNb ect dgNefuH HbKBM" ascii
    $s5  = "var jSb = (\"2.XMLHTTP soTNkdX bCzmj XML ream St CxTnwrpX AD nyktYAo O xZex D\").split(\" \");" fullword ascii
    $s6  = "function VcxTWzNkv(QVmEy) {" fullword ascii
    $s7  = "return KdzRSBn(zU,Nsnhj[902-896]+Nsnhj[324-317]+Nsnhj[428-420]);" fullword ascii
    $s8  = "function tKFo(eMwAh) {" fullword ascii
    $s9  = "function bmUIMjXnZ(XTxRfnMvWSZ) {" fullword ascii
    $s10 = "if (pbGys == 645-445){return true;} else {return false;}" fullword ascii
    $s11 = "return ynHCFZ.position=373-373;" fullword ascii
    $s12 = "function DqwH(nDKkm) {" fullword ascii
    $s13 = "return ppkR.ExpandEnvironmentStrings(fpFZy);" fullword ascii
    $s14 = "function dJXq(meySn) {" fullword ascii
    $s15 = "return yrXWC.status;" fullword ascii
    $s16 = "function nbkgLmt(KJVR) {" fullword ascii
    $s17 = "return KJVR.responseBody;" fullword ascii
    $s18 = "HYT = T; break; " fullword ascii
    $s19 = "return YADba;" fullword ascii
    $s20 = "if (M >= nDKkm.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}