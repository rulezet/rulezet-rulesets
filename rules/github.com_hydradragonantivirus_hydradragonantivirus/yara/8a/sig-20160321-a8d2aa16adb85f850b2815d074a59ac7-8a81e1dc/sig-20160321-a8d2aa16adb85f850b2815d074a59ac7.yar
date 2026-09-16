rule sig_20160321_a8d2aa16adb85f850b2815d074a59ac7 {
  meta:
    description = "datamaliciousorder - file 20160321_a8d2aa16adb85f850b2815d074a59ac7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b61978b421c9fe994486f030df17fc70bb35331d830e8d4a447227e12fab21ee"

  strings:
    $s1  = "return WScript.CreateObject(BlmxB);" fullword ascii
    $s2  = "var nd = true  , BAJC = ocP[7] + ocP[9] + ocP[11];" fullword ascii
    $s3  = "return pQMdCXi[0] + pQMdCXi[2] + pQMdCXi[4] + \".F\" + pQMdCXi[7] + pQMdCXi[9] + pQMdCXi[12] + pQMdCXi[14];" fullword ascii
    $s4  = "var pQMdCXi = wsZEA(YOoCxWqGpt+\" \"+\"System ur bLZrE Obj xyTUZe ect oAixuaS OtNHL\", \" \");" fullword ascii
    $s5  = "YZwVA.open(kUfwt,URrNI,false);" fullword ascii
    $s6  = "var ocP = (\"2.XMLHTTP ciNwsvF HScbY XML ream St DaUpAfuw AD UOMYEHM O NKYt D\").split(\" \");" fullword ascii
    $s7  = "function mZTmpAF(Vwyq) {" fullword ascii
    $s8  = "function kDFI(FSfmj) {" fullword ascii
    $s9  = "return Vwyq[VmNTFB[0]];" fullword ascii
    $s10 = "function WZdyBtGu(out) {" fullword ascii
    $s11 = "return XgvPDu.position=674-674;" fullword ascii
    $s12 = "function fSXd(BlmxB) {" fullword ascii
    $s13 = "return qMCbC.status;" fullword ascii
    $s14 = "function IDYcMeSnU(UFVqL) {" fullword ascii
    $s15 = "function RYaZ(ahkMj,Utovn) {" fullword ascii
    $s16 = "function wsZEA(FnC,iENOn) {" fullword ascii
    $s17 = "function xsKbeSGM(VxDE) {" fullword ascii
    $s18 = "function nmyrh(XgvPDu) {" fullword ascii
    $s19 = "function HVSMzIqss(SRjyHQfseFZ) {" fullword ascii
    $s20 = "return new ActiveXObject(zGjKNE);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}