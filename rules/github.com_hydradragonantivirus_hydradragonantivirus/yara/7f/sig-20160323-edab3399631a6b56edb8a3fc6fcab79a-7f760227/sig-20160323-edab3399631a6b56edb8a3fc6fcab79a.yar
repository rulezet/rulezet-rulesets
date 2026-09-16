rule sig_20160323_edab3399631a6b56edb8a3fc6fcab79a {
  meta:
    description = "datamaliciousorder - file 20160323_edab3399631a6b56edb8a3fc6fcab79a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "745108d48e9b9d836b9ceef36c197e5bcc67dd9532dd6f330088544cd669e38b"

  strings:
    $s1  = "return WScript.CreateObject(BEwuP);" fullword ascii
    $s2  = "return jqgyFNX[0] + jqgyFNX[2] + jqgyFNX[4] + \".F\" + jqgyFNX[7] + jqgyFNX[9] + jqgyFNX[12] + jqgyFNX[14];" fullword ascii
    $s3  = "var Kw = true  , nvCi = oHi[7] + oHi[9] + oHi[11];" fullword ascii
    $s4  = "var jqgyFNX = dBmwJ(jdYuNUcMAh+\" \"+\"System sp zeATA Obj arEoAx ect UcOrPHW sERDq\", \" \");" fullword ascii
    $s5  = "SSQj.open(HVvCq,ortdE,false);" fullword ascii
    $s6  = "var oHi = (\"2.XMLHTTP kOruTKk UtokX XML ream St jEdmXigp AD mtFagtO O UAto D\").split(\" \");" fullword ascii
    $s7  = "if(p>=P.length) {break;}" fullword ascii
    $s8  = "return YIkq.ExpandEnvironmentStrings(PwWBM);" fullword ascii
    $s9  = "function VRvwkAITq(dUXuMLpZcHF) {" fullword ascii
    $s10 = "function lZil(Rwmzh) {" fullword ascii
    $s11 = "function IQTFMJr(YIkq,PwWBM) {" fullword ascii
    $s12 = "return new ActiveXObject(mUpv);" fullword ascii
    $s13 = "return IQTFMJr(oq,ehTPK[653-647]+ehTPK[133-126]+ehTPK[980-972]);" fullword ascii
    $s14 = "function dBmwJ(KKQ,bJHfy) {" fullword ascii
    $s15 = "function KHDac(yZiVgx) {" fullword ascii
    $s16 = "return QYeqA;" fullword ascii
    $s17 = "function scyQhSWP(hhTq) {" fullword ascii
    $s18 = "function MeqoB(Dkpzgi) {" fullword ascii
    $s19 = "function Meus(fNwgC,ortdE,HVvCq) {" fullword ascii
    $s20 = "function XIDjYJEjC(zRIDu) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}