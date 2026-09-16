rule sig_20160308_c8164b0194a0f1f184b7d1990fe92256 {
  meta:
    description = "datamaliciousorder - file 20160308_c8164b0194a0f1f184b7d1990fe92256.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4247dc79b952024616dad9b9598b14005c89c3d9e9ef741d6a3f35d695630771"

  strings:
    $s1  = "var DT = true  , zlGt = pha[7] + pha[9] + pha[11];" fullword ascii
    $s2  = "return sflcKZg[0] + sflcKZg[2] + sflcKZg[4] + \".F\" + sflcKZg[7] + sflcKZg[9] + sflcKZg[12] + sflcKZg[14];" fullword ascii
    $s3  = "var sflcKZg = \"Sc rcoaSCR r dmjhlPPEy ipting sPURaaG MvY ile lnYzUmHiJMRgQC System RD QrxmG Obj uoDNbf ect EqYlpwU\".split(\" " ascii
    $s4  = "BusKK.open(ztBqZ,cWTKC,false);" fullword ascii
    $s5  = "var pha = (\"2.XMLHTTP NjJgLyd csEqB XML ream St aZgZxSOt AD NNZZBSL O MKKM D\").split(\" \");" fullword ascii
    $s6  = "function ipKG(KCidd,EXVUR) {" fullword ascii
    $s7  = "jBW = t; break; " fullword ascii
    $s8  = "function Bqyw(DKwmq) {" fullword ascii
    $s9  = "return Rxr.size;" fullword ascii
    $s10 = "return hbcZC;" fullword ascii
    $s11 = "return FCOXjEC" fullword ascii
    $s12 = "function zvqQ(HQISj) {" fullword ascii
    $s13 = "function PsBq(XOyBL) {" fullword ascii
    $s14 = "function AgIJ(UwRvC,taSgi) {" fullword ascii
    $s15 = "function btdQDlmRI(mtEgwIfkSpD) {" fullword ascii
    $s16 = "function TkPduUb(YdFW) {" fullword ascii
    $s17 = "function cXddQQtv() {" fullword ascii
    $s18 = "function xnHi(XSDbk) {" fullword ascii
    $s19 = "if (((new Date())>0,7556211888)) {" fullword ascii
    $s20 = "return iv.ExpandEnvironmentStrings(QjoQR[6]+QjoQR[7]+QjoQR[8]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}