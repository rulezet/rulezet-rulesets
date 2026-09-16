rule sig_20160419_2279b9e657513cc5dffa34f1f6b8d784 {
  meta:
    description = "datamaliciousorder - file 20160419_2279b9e657513cc5dffa34f1f6b8d784.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24395fadd24c98303a2d92a57632355a14c1c64151e08a99ccb6bfb9a7c45293"

  strings:
    $s1  = "return nHgFIMV[0] + nHgFIMV[2] + nHgFIMV[4] + \".F\" + nHgFIMV[7] + nHgFIMV[9] + nHgFIMV[12] + nHgFIMV[14];" fullword ascii
    $s2  = "var Lb = true  , UPsS = hLb[7] + hLb[9] + hLb[11];" fullword ascii
    $s3  = "var hLb = (\"2.XMLHTTP XUgbPNF HcfaO XML ream St CYiIgPse AD TtEtwyW O RJyz D\").split(\" \");" fullword ascii
    $s4  = "fQYm.open(ODHZe,Fgxnw,false);" fullword ascii
    $s5  = "function MkXiUUlmL(FyrWf) {" fullword ascii
    $s6  = "if(I>=t.length) {break;}" fullword ascii
    $s7  = "function wHDTJ(yaICMc) {" fullword ascii
    $s8  = "function QQqr(rTKYn,MbXmy) {" fullword ascii
    $s9  = "function JfBc(OnGrN) {" fullword ascii
    $s10 = "function dTVNIWSo(RfF) {" fullword ascii
    $s11 = "function bwRFf(gaIbVd) {" fullword ascii
    $s12 = "return JtuWy;" fullword ascii
    $s13 = "function AOsb(OaYbF,Fgxnw,ODHZe) {" fullword ascii
    $s14 = "function egaSTHR(HJEe,LMxCC) {" fullword ascii
    $s15 = "function ekuVOkk(NNjm) {" fullword ascii
    $s16 = "Smc = I; break; " fullword ascii
    $s17 = "function Efma(oGPpj) {" fullword ascii
    $s18 = "XMeQM[FoRD[353-353]](aIgBoN);" fullword ascii
    $s19 = "return wrDBTzr[0];" fullword ascii
    $s20 = "function BhYqSUrZq(yjltBjkQSYN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}