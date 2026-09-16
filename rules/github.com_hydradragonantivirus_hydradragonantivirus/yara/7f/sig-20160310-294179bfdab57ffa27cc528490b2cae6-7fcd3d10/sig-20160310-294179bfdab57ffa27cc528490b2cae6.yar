rule sig_20160310_294179bfdab57ffa27cc528490b2cae6 {
  meta:
    description = "datamaliciousorder - file 20160310_294179bfdab57ffa27cc528490b2cae6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab376b2905a23f9d00f02c9f5d5dd09287004cdd1284da909f60748f9b7b3a5a"

  strings:
    $s1  = "var Mv = true  , tsQx = UOG[7] + UOG[9] + UOG[11];" fullword ascii
    $s2  = "xmopm.open(PscFd,XeNjS,false);" fullword ascii
    $s3  = "function dBbILvRcz(hadTb,HPlge,oCgjz,cMDV) {" fullword ascii
    $s4  = "var UOG = (\"2.XMLHTTP aGhWFyZ tKRVx XML ream St oIgSaXWc AD uiHNkth O pWOG D\").split(\" \");" fullword ascii
    $s5  = "if (IvEyt == 971-771){return true;} else {return false;}" fullword ascii
    $s6  = "return euTpLhM(nP,MnSNn[204-198]+MnSNn[751-744]+MnSNn[591-583]);" fullword ascii
    $s7  = "return rPA.size;" fullword ascii
    $s8  = "function mGtEw(qZMLjO) {" fullword ascii
    $s9  = "function fhoKJcx(ayaj) {" fullword ascii
    $s10 = "return xwFLX;" fullword ascii
    $s11 = "function dndU(VoTwQ) {" fullword ascii
    $s12 = "return ayaj.responseBody;" fullword ascii
    $s13 = "function UvAEaVzU() {" fullword ascii
    $s14 = "return MKyg.ExpandEnvironmentStrings(oLvIh);" fullword ascii
    $s15 = "function iiVb(gxwbL) {" fullword ascii
    $s16 = "return gfEBk.status;" fullword ascii
    $s17 = "function oVoz(gwqFe,LTQmp) {" fullword ascii
    $s18 = "return GRAGUG.position=516-516;" fullword ascii
    $s19 = "if (R >= pgbTd.length) {break;}" fullword ascii
    $s20 = "function ZUPe(mToQI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}