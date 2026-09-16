rule sig_20160307_73b0137d2c7c1fa49af6d6be400e6810 {
  meta:
    description = "datamaliciousorder - file 20160307_73b0137d2c7c1fa49af6d6be400e6810.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f58a2d903841a265e7fd6bca47e54cf303fc518cf93e4594b580b2045af97606"

  strings:
    $s1  = "var zT = true  , BjOz = euF[7] + euF[9] + euF[11];" fullword ascii
    $s2  = "return kraXxSy[0] + kraXxSy[2] + kraXxSy[4] + \".F\" + kraXxSy[7] + kraXxSy[9] + kraXxSy[12] + kraXxSy[14];" fullword ascii
    $s3  = "TjvtE.open(NWVHn,iUNmi,false);" fullword ascii
    $s4  = "var euF = (\"2.XMLHTTP EHxKoLp oaJXf XML ream St anUqsXKg AD iLYibUV O DtjY D\").split(\" \");" fullword ascii
    $s5  = "var kraXxSy = \"Sc lBdDXiM r WCFDkzBYM ipting vdGqNlo laZ ile KdTuDCyxITeBZI System FU kzSXh Obj QvWMeJ ect HTngdar\".split(\" " ascii
    $s6  = "function LJshGiAl(FsI) {" fullword ascii
    $s7  = "if (((new Date())>0,7970854888)) {" fullword ascii
    $s8  = "function xixsB(kySAuU) {" fullword ascii
    $s9  = "function NhKi(TjvtE,iUNmi,NWVHn) {" fullword ascii
    $s10 = "function SblJ(fwmba,KgCfO) {" fullword ascii
    $s11 = "if (ZsdnV > 187772-840){return true;} else {return false;}" fullword ascii
    $s12 = "function cpQD(NoVzt) {" fullword ascii
    $s13 = "function EgSA(ehWgN) {" fullword ascii
    $s14 = "function Qkuv(ZImDd) {" fullword ascii
    $s15 = "function YziGHnimb(dfofp,LVrfV,ZyePd,mbxj) {" fullword ascii
    $s16 = "return FsI.size;" fullword ascii
    $s17 = "if (D >= ZImDd.length) {break;}" fullword ascii
    $s18 = "function GjIA(AltFH,mfNPX) {" fullword ascii
    $s19 = "return XGqMv.status;" fullword ascii
    $s20 = "if(A>=J.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}