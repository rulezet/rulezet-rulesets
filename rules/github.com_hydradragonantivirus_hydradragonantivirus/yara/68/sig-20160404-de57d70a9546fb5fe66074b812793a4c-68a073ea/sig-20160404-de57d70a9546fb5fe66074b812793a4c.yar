rule sig_20160404_de57d70a9546fb5fe66074b812793a4c {
  meta:
    description = "datamaliciousorder - file 20160404_de57d70a9546fb5fe66074b812793a4c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d4cd72086b3ff30b59b5e1ab30cdecd1e8ef761f2d935996e87da47db5eda10"

  strings:
    $s1  = "var CQ = true  , fDal = yAZ[7] + yAZ[9] + yAZ[11];" fullword ascii
    $s2  = "return XHPuIvQ[0] + XHPuIvQ[2] + XHPuIvQ[4] + \".F\" + XHPuIvQ[7] + XHPuIvQ[9] + XHPuIvQ[12] + XHPuIvQ[14];" fullword ascii
    $s3  = "AKUL.open(NGcvc,NfnQF,false);" fullword ascii
    $s4  = "var XHPuIvQ = tYBaI(edlsjNZjqr+\" \"+\"System EA xosDG Obj ZRtCfj ect aOUnQAg pIsfj\", \" \");" fullword ascii
    $s5  = "if(D>=Q.length) {break;}" fullword ascii
    $s6  = "return VHaK;" fullword ascii
    $s7  = "function SKZj(LziVy,NyNLj) {" fullword ascii
    $s8  = "var CGYBwKC = \"NmQslA*AUf*pt.S\"+\"hell*CVpEvIE*Scri*\";" fullword ascii
    $s9  = "return dur.split(JUHwb);" fullword ascii
    $s10 = "function Fopvn(MafCBG) {" fullword ascii
    $s11 = "function AOIL(DXCqg,NfnQF,NGcvc) {" fullword ascii
    $s12 = "function xwwvy(UIbYDE) {" fullword ascii
    $s13 = "return XBFeK.status;" fullword ascii
    $s14 = "function rkQq(zMgyG) {" fullword ascii
    $s15 = "return kpX.size;" fullword ascii
    $s16 = "function huFD(OEYQR) {" fullword ascii
    $s17 = "MWT = D; break; " fullword ascii
    $s18 = "function TvoM(cpYia) {" fullword ascii
    $s19 = "function Tuwaj(ykxZjFUq,wvFd) {" fullword ascii
    $s20 = "return RFvtIaM;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}