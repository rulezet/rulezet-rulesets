rule sig_20160311_7f9a3728290643543626cbf909777d16 {
  meta:
    description = "datamaliciousorder - file 20160311_7f9a3728290643543626cbf909777d16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "973bbd2397853f622a508c7bcc087c42cc6538f22844c6126899f6cb7064575e"

  strings:
    $s1  = "var ur = true  , czYF = NLt[7] + NLt[9] + NLt[11];" fullword ascii
    $s2  = "return UYrqVRx[0] + UYrqVRx[2] + UYrqVRx[4] + \".F\" + UYrqVRx[7] + UYrqVRx[9] + UYrqVRx[12] + UYrqVRx[14];" fullword ascii
    $s3  = "var NLt = (\"2.XMLHTTP axdBmxv wdmQo XML ream St fSWGTeVA AD MGWyRtL O Fpfd D\").split(\" \");" fullword ascii
    $s4  = "var UYrqVRx = \"Sc iXAsDex r brJdGtJcW ipting jwjEGGk uzB ile MPTimruQpyfhKU System Az vvsDR Obj DxiCos ect gVxmZKT\".split(\" " ascii
    $s5  = "mnieX.open(quXrc,enCxm,false);" fullword ascii
    $s6  = "SXA = z; break; " fullword ascii
    $s7  = "if (oGrZc == 834-634){return true;} else {return false;}" fullword ascii
    $s8  = "function dnAL(ybHVa,OHlFD) {" fullword ascii
    $s9  = "function JaXm(cWJHw) {" fullword ascii
    $s10 = "function GzDhiaThj() {" fullword ascii
    $s11 = "function LoCe(mnieX,enCxm,quXrc) {" fullword ascii
    $s12 = "return QClUmz.position=122-122;" fullword ascii
    $s13 = "return BAyM.responseBody;" fullword ascii
    $s14 = "function WBMJROpTF(TAxTNFidLHz) {" fullword ascii
    $s15 = "return IyeKZYu(Zt,tDIzf[969-963]+tDIzf[196-189]+tDIzf[378-370]);" fullword ascii
    $s16 = "function SGubjuBW(BNrFd,GhsOyS) {" fullword ascii
    $s17 = "return LyZe.ExpandEnvironmentStrings(lGtCc);" fullword ascii
    $s18 = "function AVyrpNQ(BAyM) {" fullword ascii
    $s19 = "return JxD.size;" fullword ascii
    $s20 = "function HUdJ(WiAJS,JprHK) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}