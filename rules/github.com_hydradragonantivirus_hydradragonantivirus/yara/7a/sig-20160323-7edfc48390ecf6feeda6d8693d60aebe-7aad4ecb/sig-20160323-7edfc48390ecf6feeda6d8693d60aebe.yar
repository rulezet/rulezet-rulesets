rule sig_20160323_7edfc48390ecf6feeda6d8693d60aebe {
  meta:
    description = "datamaliciousorder - file 20160323_7edfc48390ecf6feeda6d8693d60aebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a278d51822cbda4e9b1cc05b955ec6c523476acec7e35d0f80336bcdf55bdad"

  strings:
    $s1  = "return WScript.CreateObject(llhDA);" fullword ascii
    $s2  = "return ovqtXrA[0] + ovqtXrA[2] + ovqtXrA[4] + \".F\" + ovqtXrA[7] + ovqtXrA[9] + ovqtXrA[12] + ovqtXrA[14];" fullword ascii
    $s3  = "var cs = true  , LhOB = YwQ[7] + YwQ[9] + YwQ[11];" fullword ascii
    $s4  = "var YwQ = (\"2.XMLHTTP kxgfTQV kaTUM XML ream St wyqGyeEd AD uUmkeui O shRv D\").split(\" \");" fullword ascii
    $s5  = "var ovqtXrA = MmPCx(EkxpOuCgEd+\" \"+\"System or qxyEN Obj lXJpJi ect sbFzatU aIotH\", \" \");" fullword ascii
    $s6  = "Vxyu.open(RqLbP,xOXya,false);" fullword ascii
    $s7  = "return ymbWb.status;" fullword ascii
    $s8  = "return wtrVx;" fullword ascii
    $s9  = "return IFd.size;" fullword ascii
    $s10 = "JUF = l; break; " fullword ascii
    $s11 = "function JOfY(ymbWb) {" fullword ascii
    $s12 = "return OUXh[dxIcXi[0]];" fullword ascii
    $s13 = "function JKkTY(PeeSHV) {" fullword ascii
    $s14 = "if (lDpNg > 176529-730){return true;} else {return false;}" fullword ascii
    $s15 = "return WetiICD(vJ,Cywkf[343-337]+Cywkf[562-555]+Cywkf[484-476]);" fullword ascii
    $s16 = "function uEwkRVMTJ(Nviev) {" fullword ascii
    $s17 = "function ssJy(lDpNg) {" fullword ascii
    $s18 = "function nAgS(jrXjZ) {" fullword ascii
    $s19 = "function flwS(EvpgZ,qZpmH) {" fullword ascii
    $s20 = "return new ActiveXObject(uoRa);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}