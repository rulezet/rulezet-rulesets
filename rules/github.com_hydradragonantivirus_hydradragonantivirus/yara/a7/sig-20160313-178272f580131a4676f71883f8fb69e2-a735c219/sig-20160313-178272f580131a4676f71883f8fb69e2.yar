rule sig_20160313_178272f580131a4676f71883f8fb69e2 {
  meta:
    description = "datamaliciousorder - file 20160313_178272f580131a4676f71883f8fb69e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "265ff599c9fa8013bd29b6ecb3a34005addfa3baaf52a6ec0cdf64d5828048cb"

  strings:
    $s1  = "return grFgTsi[0] + grFgTsi[2] + grFgTsi[4] + \".F\" + grFgTsi[7] + grFgTsi[9] + grFgTsi[12] + grFgTsi[14];" fullword ascii
    $s2  = "var ve = true  , HCIM = vHz[7] + vHz[9] + vHz[11];" fullword ascii
    $s3  = "var grFgTsi = \"Sc kzZRAPX r YhwoHSNFD ipting tKzqCnK Iio ile EPRVcjaRMnBxeA System cY ylych Obj rQAJSM ect ObpTbgq\".split(\" " ascii
    $s4  = "aALkm.open(gbZSe,CwTfT,false);" fullword ascii
    $s5  = "var vHz = (\"2.XMLHTTP ApdlAAb lPMcU XML ream St PsStwIyR AD keTxzXO O vvwF D\").split(\" \");" fullword ascii
    $s6  = "function umvt(BjRES) {" fullword ascii
    $s7  = "function batXimuyc(BqdvTFXAWXD) {" fullword ascii
    $s8  = "function okQL(NaBNw) {" fullword ascii
    $s9  = "function FnwfxOE(JajJ,cciXi) {" fullword ascii
    $s10 = "return hzt.size;" fullword ascii
    $s11 = "function LHOn(TcBKt) {" fullword ascii
    $s12 = "function TwEM(GQDkA) {" fullword ascii
    $s13 = "if(s>=c.length) {break;}" fullword ascii
    $s14 = "function NPEQ(bdtoc) {" fullword ascii
    $s15 = "if (pvpJX > 186524-628){return true;} else {return false;}" fullword ascii
    $s16 = "function xyop(pvpJX) {" fullword ascii
    $s17 = "function BkECKtClb() {" fullword ascii
    $s18 = "function NRYeD(ToWLUT) {" fullword ascii
    $s19 = "if (NaBNw == 1192-992){return true;} else {return false;}" fullword ascii
    $s20 = "function hBEk(vUQkr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}