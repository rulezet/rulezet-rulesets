rule sig_20160313_8fe8396e933976c7d451a698c2cecaa1 {
  meta:
    description = "datamaliciousorder - file 20160313_8fe8396e933976c7d451a698c2cecaa1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15fbd86af823a79b8014aa8bdf8fe8f50de995d517a05aa1f89083a758107784"

  strings:
    $s1  = "return dfIidab[0] + dfIidab[2] + dfIidab[4] + \".F\" + dfIidab[7] + dfIidab[9] + dfIidab[12] + dfIidab[14];" fullword ascii
    $s2  = "var sj = true  , EZyR = fxH[7] + fxH[9] + fxH[11];" fullword ascii
    $s3  = "var dfIidab = \"Sc PfqYzJO r BmtrnPHhI ipting meuGcso Dkb ile XUOYhZfWTzaaRW System hD btdxa Obj qVXCno ect jZGuNRS\".split(\" " ascii
    $s4  = "var fxH = (\"2.XMLHTTP rMwSISA ZvCrN XML ream St JTZyCqFS AD VniOfrq O aorx D\").split(\" \");" fullword ascii
    $s5  = "SGBoT.open(wWybp,vLKvO,false);" fullword ascii
    $s6  = "return VOyS.responseBody;" fullword ascii
    $s7  = "return KGtxnr.position=693-693;" fullword ascii
    $s8  = "function TwiE(prSuV) {" fullword ascii
    $s9  = "function OTPd(CDAif,dQgHJ) {" fullword ascii
    $s10 = "function iTiEi(KGtxnr) {" fullword ascii
    $s11 = "return wEW.size;" fullword ascii
    $s12 = "return new ActiveXObject(uGphFH);" fullword ascii
    $s13 = "function OmoYAlnV(wEW) {" fullword ascii
    $s14 = "if(I>=v.length) {break;}" fullword ascii
    $s15 = "uYM = I; break; " fullword ascii
    $s16 = "function NABwRMaDf() {" fullword ascii
    $s17 = "function BnFhJGQRs(jNZPVaFcelz) {" fullword ascii
    $s18 = "function gLJZPZD(VOyS) {" fullword ascii
    $s19 = "return Wsfd.ExpandEnvironmentStrings(CtfPv);" fullword ascii
    $s20 = "function NRQL(rDVoX) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}