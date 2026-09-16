rule sig_20160321_6a339139f4b7837c79aaa6ad961c20d9 {
  meta:
    description = "datamaliciousorder - file 20160321_6a339139f4b7837c79aaa6ad961c20d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f651dc38c19b29f6442dea3edd24b708d89a77665734d26dade36034a32e92b9"

  strings:
    $s1  = "return WScript.CreateObject(RxDxq);" fullword ascii
    $s2  = "return khwZFIP[0] + khwZFIP[2] + khwZFIP[4] + \".F\" + khwZFIP[7] + khwZFIP[9] + khwZFIP[12] + khwZFIP[14];" fullword ascii
    $s3  = "var vl = true  , waQg = Qrj[7] + Qrj[9] + Qrj[11];" fullword ascii
    $s4  = "var Qrj = (\"2.XMLHTTP CtvNFnz zrQQJ XML ream St AiqxRhOQ AD rbbfkyX O Adpx D\").split(\" \");" fullword ascii
    $s5  = "var khwZFIP = TjODy(CUJRqQHtuH+\" \"+\"System gc psCTx Obj OUUvPc ect fdOrQEf cjhWD\", \" \");" fullword ascii
    $s6  = "BbwOy.open(UyoQb,qorwQ,false);" fullword ascii
    $s7  = "function yhMA(KHVse) {" fullword ascii
    $s8  = "return ZlOll.status;" fullword ascii
    $s9  = "return UjOsJ;" fullword ascii
    $s10 = "function bvaP(Ajjqm,RAfVO) {" fullword ascii
    $s11 = "return vie.size;" fullword ascii
    $s12 = "return vSP.split(Rzzds);" fullword ascii
    $s13 = "function WgyK(BbwOy,qorwQ,UyoQb) {" fullword ascii
    $s14 = "return new ActiveXObject(olssJA);" fullword ascii
    $s15 = "function TjODy(vSP,Rzzds) {" fullword ascii
    $s16 = "function TQsXkTdKi(wnDznPKHHsQ) {" fullword ascii
    $s17 = "LDv = r; break; " fullword ascii
    $s18 = "function ouep(ctjor) {" fullword ascii
    $s19 = "function VEoX(SHtrd,kYkCi) {" fullword ascii
    $s20 = "function AKNPE(olssJA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}