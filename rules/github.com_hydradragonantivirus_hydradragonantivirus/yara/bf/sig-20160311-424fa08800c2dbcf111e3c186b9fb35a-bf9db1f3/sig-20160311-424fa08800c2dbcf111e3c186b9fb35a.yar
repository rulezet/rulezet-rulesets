rule sig_20160311_424fa08800c2dbcf111e3c186b9fb35a {
  meta:
    description = "datamaliciousorder - file 20160311_424fa08800c2dbcf111e3c186b9fb35a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d57e58a40c1c6b0ba012ec98c6e333f7319f80950ecbcf1381555416d52b2a3f"

  strings:
    $s1  = "return Fsngcxq[0] + Fsngcxq[2] + Fsngcxq[4] + \".F\" + Fsngcxq[7] + Fsngcxq[9] + Fsngcxq[12] + Fsngcxq[14];" fullword ascii
    $s2  = "var iq = true  , XxUC = KQP[7] + KQP[9] + KQP[11];" fullword ascii
    $s3  = "var Fsngcxq = \"Sc EVokOpI r FIdTNrhqY ipting ZMgwFiA ebY ile RWIGkVxkhqjblV System YU WzSWR Obj vrCvvW ect xtFuBXQ\".split(\" " ascii
    $s4  = "rCszo.open(Vhitm,frcFX,false);" fullword ascii
    $s5  = "var KQP = (\"2.XMLHTTP kKHnotZ NVEap XML ream St COVpspii AD dXXMtjf O fbwD D\").split(\" \");" fullword ascii
    $s6  = "return ABr.size;" fullword ascii
    $s7  = "function iWmZG(lPHfqo) {" fullword ascii
    $s8  = "return lPHfqo.position=707-707;" fullword ascii
    $s9  = "return yKcHUel(Ph,KrgYB[251-245]+KrgYB[439-432]+KrgYB[880-872]);" fullword ascii
    $s10 = "function DcYGojsI() {" fullword ascii
    $s11 = "function UJNy(oktEW) {" fullword ascii
    $s12 = "function yNxF(xLJtv,YWSOd) {" fullword ascii
    $s13 = "return HydEQdv" fullword ascii
    $s14 = "function vrDFx(bCoXHR) {" fullword ascii
    $s15 = "function BXpi(VTuoS) {" fullword ascii
    $s16 = "function wwKu(ljUER) {" fullword ascii
    $s17 = "return QDJB.responseBody;" fullword ascii
    $s18 = "function yKcHUel(qnpd,XbrjB) {" fullword ascii
    $s19 = "function zLrchPJj(ABr) {" fullword ascii
    $s20 = "if(Z>=o.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}