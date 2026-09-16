rule sig_20160405_8a89763f29d41dbbe2057b2f9ff2e516 {
  meta:
    description = "datamaliciousorder - file 20160405_8a89763f29d41dbbe2057b2f9ff2e516.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10b2c012cb129556781ff3d5140ecc0d5fe092029fdc5e1876ea414df0ed3520"

  strings:
    $s1  = "function fwyxaj(EyEBAAl) {" fullword ascii
    $s2  = "return DHouOJN[0] + DHouOJN[2] + DHouOJN[4] + \".F\" + DHouOJN[7] + DHouOJN[9] + DHouOJN[12] + DHouOJN[14];" fullword ascii
    $s3  = "var Iz = true  , ctww = gHo[7] + gHo[9] + gHo[11];" fullword ascii
    $s4  = "GXJn.open(eSzlk,gUmNn,false);" fullword ascii
    $s5  = "var gHo = (\"2.XMLHTTP xwBwsmE mwpxk XML ream St mQajcWJp AD aldYFzD O nnbW D\").split(\" \");" fullword ascii
    $s6  = "if(x>=d.length) {break;}" fullword ascii
    $s7  = "function dwPS(nGqaa,gUmNn,eSzlk) {" fullword ascii
    $s8  = "return new ActiveXObject(BkRE);" fullword ascii
    $s9  = "function nMHTC(fulosfgu,EwfG) {" fullword ascii
    $s10 = "var UeQxh = FcpgQ(sfurzgb+\"WAKA*%TE*MP%*\\\\*ZohdgXslc*iNgqwC*BnOtMBR*IZMxE\", \"*\");" fullword ascii
    $s11 = "function TIDy(Ydgbg,EMTGI) {" fullword ascii
    $s12 = "return lEAu[cCpYtJ[0]];" fullword ascii
    $s13 = "function yWCV(adLcc) {" fullword ascii
    $s14 = "function MqxUktAbt(WXGFQ) {" fullword ascii
    $s15 = "function gkdT(QRzPz) {" fullword ascii
    $s16 = "Gls = x; break; " fullword ascii
    $s17 = "function YtUBgmzpL(dkQAnbRdqvI) {" fullword ascii
    $s18 = "function yBDO(Rvycq) {" fullword ascii
    $s19 = "return nfWh;" fullword ascii
    $s20 = "function YMhD(zotFO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}