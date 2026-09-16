rule sig_20160313_ccc1bb8e5a0174e579f5981ccd9b3fd2 {
  meta:
    description = "datamaliciousorder - file 20160313_ccc1bb8e5a0174e579f5981ccd9b3fd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d31da63468e0af689a15f764b44adb14d8433b4530268b4d2c0688fc244bc48d"

  strings:
    $s1  = "return YdWjuUn[0] + YdWjuUn[2] + YdWjuUn[4] + \".F\" + YdWjuUn[7] + YdWjuUn[9] + YdWjuUn[12] + YdWjuUn[14];" fullword ascii
    $s2  = "var CT = true  , iHgA = bgH[7] + bgH[9] + bgH[11];" fullword ascii
    $s3  = "var bgH = (\"2.XMLHTTP rzinJKj qZDsg XML ream St HDMGBsme AD WriwzMa O dfpG D\").split(\" \");" fullword ascii
    $s4  = "var YdWjuUn = \"Sc WpCZXfp r PzjZKxtfQ ipting BXgalpP jwK ile IQFGyLNmMOpvTq System lY vZqKx Obj YWtljp ect PyrGaTJ\".split(\" " ascii
    $s5  = "eUMYN.open(bMOYl,bFDBI,false);" fullword ascii
    $s6  = "return UDAOB.status;" fullword ascii
    $s7  = "return BvzuQey(JJ,JjfkA[574-568]+JjfkA[530-523]+JjfkA[863-855]);" fullword ascii
    $s8  = "function YDeF(yluCO) {" fullword ascii
    $s9  = "function OWIw(WxiAu) {" fullword ascii
    $s10 = "return lAvK.ExpandEnvironmentStrings(Gxzuo);" fullword ascii
    $s11 = "function FfLx(wjIXw,bDSWC) {" fullword ascii
    $s12 = "function ZFdb(WLbXv) {" fullword ascii
    $s13 = "function FxHVflgv(OIx) {" fullword ascii
    $s14 = "if (DyuJD > 150252-196){return true;} else {return false;}" fullword ascii
    $s15 = "return xQmLHF.position=596-596;" fullword ascii
    $s16 = "return OIx.size;" fullword ascii
    $s17 = "function ilZFU(xQmLHF) {" fullword ascii
    $s18 = "return dcUdR;" fullword ascii
    $s19 = "function BvzuQey(lAvK,Gxzuo) {" fullword ascii
    $s20 = "function uPgn(NonEC) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}