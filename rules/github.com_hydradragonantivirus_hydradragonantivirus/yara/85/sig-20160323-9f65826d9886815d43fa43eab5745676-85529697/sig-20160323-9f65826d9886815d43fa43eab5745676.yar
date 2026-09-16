rule sig_20160323_9f65826d9886815d43fa43eab5745676 {
  meta:
    description = "datamaliciousorder - file 20160323_9f65826d9886815d43fa43eab5745676.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a54e37c73d142fb704c1998961d24e1243c99b06fcdde9131fae67507f026cb3"

  strings:
    $s1  = "return WScript.CreateObject(BnpKc);" fullword ascii
    $s2  = "return VCpWwPe[0] + VCpWwPe[2] + VCpWwPe[4] + \".F\" + VCpWwPe[7] + VCpWwPe[9] + VCpWwPe[12] + VCpWwPe[14];" fullword ascii
    $s3  = "var LH = true  , BPht = bXC[7] + bXC[9] + bXC[11];" fullword ascii
    $s4  = "var bXC = (\"2.XMLHTTP DNAppTg fEDCH XML ream St FfoSYnLm AD KCNcIqv O HPPd D\").split(\" \");" fullword ascii
    $s5  = "var VCpWwPe = mtjSU(PwizUuUsJw+\" \"+\"System zT GipIT Obj gJVtqV ect SdiIBnz MPEHM\", \" \");" fullword ascii
    $s6  = "FDOS.open(hzEwi,gHCwN,false);" fullword ascii
    $s7  = "if (gvQls == 772-572){return true;} else {return false;}" fullword ascii
    $s8  = "function GXnaRYBka(osVcV) {" fullword ascii
    $s9  = "function mtjSU(gmI,ixkDV) {" fullword ascii
    $s10 = "function UQRo(ASiez,faTtJ) {" fullword ascii
    $s11 = "function QTaJ(OJtBH) {" fullword ascii
    $s12 = "return NJh.size;" fullword ascii
    $s13 = "function uklZviAg(KUDk) {" fullword ascii
    $s14 = "return LnnHmVR(cE,lEqkg[180-174]+lEqkg[483-476]+lEqkg[903-895]);" fullword ascii
    $s15 = "function LnnHmVR(VkSP,wYoAR) {" fullword ascii
    $s16 = "function CuCxkmEGs(YiyobJYYhCT) {" fullword ascii
    $s17 = "function aljp(gvQls) {" fullword ascii
    $s18 = "function xoTR(jFhgL) {" fullword ascii
    $s19 = "function slOA(YysOj) {" fullword ascii
    $s20 = "function GhCSCBsl(NJh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}