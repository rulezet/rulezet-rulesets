rule sig_20160315_3e11218526a33072bca049b66025e605 {
  meta:
    description = "datamaliciousorder - file 20160315_3e11218526a33072bca049b66025e605.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff9f4d0a41f2f0b3a3ec528245f26acc05c83fe41e07eae49ecc189638238a14"

  strings:
    $s1  = "return daMN.ExpandEnvironmentStrings(bNJGo);" fullword ascii
    $s2  = "function AfcZqRv(daMN,bNJGo) {" fullword ascii
    $s3  = "return xcfvEXX[0] + xcfvEXX[2] + xcfvEXX[4] + \".F\" + xcfvEXX[7] + xcfvEXX[9] + xcfvEXX[12] + xcfvEXX[14];" fullword ascii
    $s4  = "var Ws = true  , MzyB = GSg[7] + GSg[9] + GSg[11];" fullword ascii
    $s5  = "var GSg = (\"2.XMLHTTP kpZAMqA KZpNW XML ream St AWpAXMdg AD fAnDpRP O kunS D\").split(\" \");" fullword ascii
    $s6  = "HyAMJ.open(gcdmH,tihOM,false);" fullword ascii
    $s7  = "var xcfvEXX = YfGAm(\"Sc nRKrhCn r RfkXQLGbU ipting sCBSBsB cjP ile XQdEczCrDYiPqT System kE RcxJu Obj tEJcTv ect brRgwOe eCshl" ascii
    $s8  = "var xcfvEXX = YfGAm(\"Sc nRKrhCn r RfkXQLGbU ipting sCBSBsB cjP ile XQdEczCrDYiPqT System kE RcxJu Obj tEJcTv ect brRgwOe eCshl" ascii
    $s9  = "function JhRdyip(fkkb) {" fullword ascii
    $s10 = "function YfGAm(DLk,ixyhu) {" fullword ascii
    $s11 = "function ofUS(agrCx) {" fullword ascii
    $s12 = "function NMcWy(lDVwHS) {" fullword ascii
    $s13 = "function NBgE(bRKJd) {" fullword ascii
    $s14 = "return sFKQgoa" fullword ascii
    $s15 = "function IKfQdiTLf(ZemTR) {" fullword ascii
    $s16 = "function KvWtKogFt(cFhCCFOlrod) {" fullword ascii
    $s17 = "function HmPc(ZgfNl) {" fullword ascii
    $s18 = "function yqBs(HyAMJ,tihOM,gcdmH) {" fullword ascii
    $s19 = "return QGnbN;" fullword ascii
    $s20 = "function DgdBpetV() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}