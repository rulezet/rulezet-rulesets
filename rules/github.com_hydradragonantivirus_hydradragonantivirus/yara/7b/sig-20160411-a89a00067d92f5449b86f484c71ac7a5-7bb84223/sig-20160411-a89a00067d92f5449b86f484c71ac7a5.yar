rule sig_20160411_a89a00067d92f5449b86f484c71ac7a5 {
  meta:
    description = "datamaliciousorder - file 20160411_a89a00067d92f5449b86f484c71ac7a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b37b62c43413661b74f6ce669095d902c854d9cbd9ba335ec080011c53cdaa6e"

  strings:
    $s1  = "var GA = true  , AswB = pMt[7] + pMt[9] + pMt[11];" fullword ascii
    $s2  = "return ngilOXG[0] + ngilOXG[2] + ngilOXG[4] + \".F\" + ngilOXG[7] + ngilOXG[9] + ngilOXG[12] + ngilOXG[14];" fullword ascii
    $s3  = "var pMt = (\"2.XMLHTTP FpLAVaa VddUF XML ream St npQXjYzK AD ehVTDUO O ZKxr D\").split(\" \");" fullword ascii
    $s4  = "lbDn.open(Qkcxi,xlnry,false);" fullword ascii
    $s5  = "function EMzM(vZAGE,CwYMQ) {" fullword ascii
    $s6  = "function wPLX(vAtcs) {" fullword ascii
    $s7  = "function xZJVZh(eMQGXKW) {" fullword ascii
    $s8  = "if (xOoIC == 675-475){return true;} else {return false;}" fullword ascii
    $s9  = "function IYAT(ixryt,xlnry,Qkcxi) {" fullword ascii
    $s10 = "return jyJXz.status;" fullword ascii
    $s11 = "LIj = K; break; " fullword ascii
    $s12 = "function KNXmsFK(DfUA,qwQmp) {" fullword ascii
    $s13 = "function phPuWEEdH(UmtKx) {" fullword ascii
    $s14 = "function yDAacvrm(KdCr) {" fullword ascii
    $s15 = "function ymOkL(FNQJPc) {" fullword ascii
    $s16 = "function VuTX(VHIlx) {" fullword ascii
    $s17 = "function ibAtFdf(qqdX) {" fullword ascii
    $s18 = "return jwklYHs[0];" fullword ascii
    $s19 = "return SyGwPPw;" fullword ascii
    $s20 = "return new ActiveXObject(TfnZ);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}