rule sig_20160322_95c898526ecbfa353180aeae48fd5948 {
  meta:
    description = "datamaliciousorder - file 20160322_95c898526ecbfa353180aeae48fd5948.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68d0514744d22981f31837802f7a8f2f986b84acf0998b55e69b83ead9415428"

  strings:
    $s1  = "return WScript.CreateObject(UECBy);" fullword ascii
    $s2  = "var hO = true  , UhaU = OUD[7] + OUD[9] + OUD[11];" fullword ascii
    $s3  = "return KsWiAax[0] + KsWiAax[2] + KsWiAax[4] + \".F\" + KsWiAax[7] + KsWiAax[9] + KsWiAax[12] + KsWiAax[14];" fullword ascii
    $s4  = "var KsWiAax = GjoBh(oSnUXhuNXT+\" \"+\"System ui foYnX Obj PdoJOc ect wGTtprd MthEy\", \" \");" fullword ascii
    $s5  = "var OUD = (\"2.XMLHTTP FNAGPxg lYibe XML ream St xZsnuiMS AD JSwJeLA O KeDf D\").split(\" \");" fullword ascii
    $s6  = "kJJK.open(Vongx,ZNlFu,false);" fullword ascii
    $s7  = "return aaj.size;" fullword ascii
    $s8  = "function GUMX(noGbV) {" fullword ascii
    $s9  = "function Hmxc(aiJwW) {" fullword ascii
    $s10 = "return dao.split(jgpjH);" fullword ascii
    $s11 = "return Tbmjo;" fullword ascii
    $s12 = "function TBWo(ZNKzP,Ryikv) {" fullword ascii
    $s13 = "function TBee(UzUGh,noxHv) {" fullword ascii
    $s14 = "return new ActiveXObject(lyQJnX);" fullword ascii
    $s15 = "function DOdEX(HWeUdo) {" fullword ascii
    $s16 = "if(W>=H.length) {break;}" fullword ascii
    $s17 = "function yyaD(jpvor) {" fullword ascii
    $s18 = "return HWeUdo.position=775-775;" fullword ascii
    $s19 = "function lOsYwwTc(aaj) {" fullword ascii
    $s20 = "function cZKTlTyGU(ATxFs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}