rule sig_20160405_5a2330f05c4bdf47ff685653000b81a7 {
  meta:
    description = "datamaliciousorder - file 20160405_5a2330f05c4bdf47ff685653000b81a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46ac328351331014dddf8bf1c019b64d3827b0328cfa493d7cf03c66a7355f93"

  strings:
    $s1  = "var lx = true  , fDXw = tFU[7] + tFU[9] + tFU[11];" fullword ascii
    $s2  = "return kUnyzhx[0] + kUnyzhx[2] + kUnyzhx[4] + \".F\" + kUnyzhx[7] + kUnyzhx[9] + kUnyzhx[12] + kUnyzhx[14];" fullword ascii
    $s3  = "HkoA.open(dYYnX,ILKRl,false);" fullword ascii
    $s4  = "var tFU = (\"2.XMLHTTP YPlllvq CxmbU XML ream St XdpQuyGf AD sCDKziA O dLav D\").split(\" \");" fullword ascii
    $s5  = "function ZWtp(XAFDG) {" fullword ascii
    $s6  = "return VsNW;" fullword ascii
    $s7  = "function xwGN(FAyud) {" fullword ascii
    $s8  = "function onRUYr(WpoUpfX) {" fullword ascii
    $s9  = "return FAyud.status;" fullword ascii
    $s10 = "function Ceqm(AmmOy) {" fullword ascii
    $s11 = "return Voa.split(hQRLr);" fullword ascii
    $s12 = "function IfYh(Rnnwp) {" fullword ascii
    $s13 = "function VVRi(KLxgA) {" fullword ascii
    $s14 = "function oKndY(HSAtRj) {" fullword ascii
    $s15 = "return Tbs.size;" fullword ascii
    $s16 = "function uZZp(UAVcZ,ILKRl,dYYnX) {" fullword ascii
    $s17 = "if(U>=F.length) {break;}" fullword ascii
    $s18 = "function elNoQKPqF(PTIGa) {" fullword ascii
    $s19 = "function QTOKYTQTf(IlBloaGLXPI) {" fullword ascii
    $s20 = "return GRPt[eZzDNr[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}