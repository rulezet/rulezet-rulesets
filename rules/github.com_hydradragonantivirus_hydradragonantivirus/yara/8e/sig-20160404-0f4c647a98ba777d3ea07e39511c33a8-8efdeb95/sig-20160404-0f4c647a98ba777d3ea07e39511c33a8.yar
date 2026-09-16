rule sig_20160404_0f4c647a98ba777d3ea07e39511c33a8 {
  meta:
    description = "datamaliciousorder - file 20160404_0f4c647a98ba777d3ea07e39511c33a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d7fe2bccfc5964851927f5bc657f24179e2ee4b4686c5e7efdb864c08de4d0d"

  strings:
    $s1  = "var oa = true  , MqcJ = sfe[7] + sfe[9] + sfe[11];" fullword ascii
    $s2  = "return vrDxZsj[0] + vrDxZsj[2] + vrDxZsj[4] + \".F\" + vrDxZsj[7] + vrDxZsj[9] + vrDxZsj[12] + vrDxZsj[14];" fullword ascii
    $s3  = "var sfe = (\"2.XMLHTTP kdrFWjx UsjVq XML ream St hubBPuSZ AD VVKhklk O MesL D\").split(\" \");" fullword ascii
    $s4  = "mjOo.open(oGQjK,kPWLH,false);" fullword ascii
    $s5  = "var vrDxZsj = pWIXl(fONGZvRXsP+\" \"+\"System XQ LBgYW Obj OJjpXH ect iGqzpnH RfvtK\", \" \");" fullword ascii
    $s6  = "if(i>=J.length) {break;}" fullword ascii
    $s7  = "function Nmmdq(lCXxHC) {" fullword ascii
    $s8  = "return ctoKnWC(De,FEDAv[954-948]+FEDAv[594-587]+FEDAv[246-238]);" fullword ascii
    $s9  = "return xHL.size;" fullword ascii
    $s10 = "if (b >= DzHru.length) {break;}" fullword ascii
    $s11 = "function NkKsHmaKm(sqGxqzDAUpv) {" fullword ascii
    $s12 = "function aDba(zMtkr,kPWLH,oGQjK) {" fullword ascii
    $s13 = "function wvjVUdNI(CUMM) {" fullword ascii
    $s14 = "return \"zcqkMlHNRgYmOk\";" fullword ascii
    $s15 = "return IQANrbT;" fullword ascii
    $s16 = "if (etpux == 778-578){return true;} else {return false;}" fullword ascii
    $s17 = "function AZjd(DzHru) {" fullword ascii
    $s18 = "function VWlV(XLTYw) {" fullword ascii
    $s19 = "return tKqPF;" fullword ascii
    $s20 = "function SBth(wuQbA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}