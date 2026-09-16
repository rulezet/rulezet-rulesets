rule sig_20160313_66b201fd1ef15c7e23fc6fccd17ddd76 {
  meta:
    description = "datamaliciousorder - file 20160313_66b201fd1ef15c7e23fc6fccd17ddd76.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "336c6bf9095512d41c53972c68fd5f37e018f1d319cf8f54fe5481920fa4928a"

  strings:
    $s1  = "var JH = true  , uIsO = lkA[7] + lkA[9] + lkA[11];" fullword ascii
    $s2  = "return eWiYpXP[0] + eWiYpXP[2] + eWiYpXP[4] + \".F\" + eWiYpXP[7] + eWiYpXP[9] + eWiYpXP[12] + eWiYpXP[14];" fullword ascii
    $s3  = "var lkA = (\"2.XMLHTTP bdyUOiD dSSHQ XML ream St vyDpcFpm AD zQiZbNn O EUXE D\").split(\" \");" fullword ascii
    $s4  = "TkYIq.open(KGAFw,JDpLa,false);" fullword ascii
    $s5  = "var eWiYpXP = \"Sc pipUZLY r PjusUeHxm ipting ChRWHuq XvC ile kPXpiIpjRamzhR System AI hUtLU Obj uoyYNr ect gQuyTYr\".split(\" " ascii
    $s6  = "function XMSr(OSZJn) {" fullword ascii
    $s7  = "function XAgy(uRaQm) {" fullword ascii
    $s8  = "function QMMZo(FKzINZ) {" fullword ascii
    $s9  = "function zOab(kqmOC) {" fullword ascii
    $s10 = "return new ActiveXObject(FKzINZ);" fullword ascii
    $s11 = "if (oeqNm > 185548-929){return true;} else {return false;}" fullword ascii
    $s12 = "return Xjgt.ExpandEnvironmentStrings(WaYdD);" fullword ascii
    $s13 = "return jraIYy.position=443-443;" fullword ascii
    $s14 = "if (OSZJn == 494-294){return true;} else {return false;}" fullword ascii
    $s15 = "function viCHFvic() {" fullword ascii
    $s16 = "function iaZv(RJGuS) {" fullword ascii
    $s17 = "function JnxA(HpydZ,EEgCG) {" fullword ascii
    $s18 = "function zASe(zCtVz,drlnY) {" fullword ascii
    $s19 = "function dERgqYCbW(EHAlwjVUFKN) {" fullword ascii
    $s20 = "function GrRv(iRtAd) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}