rule sig_20160323_a7c1ee15db0f2c41319f49f4393b5baa {
  meta:
    description = "datamaliciousorder - file 20160323_a7c1ee15db0f2c41319f49f4393b5baa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f957de3614cdd815b877fc2f3dc75e6b2aabe6b0e8bffc4afd8649c5fa044626"

  strings:
    $s1  = "return WScript.CreateObject(cqmwd);" fullword ascii
    $s2  = "var oj = true  , JWaF = AnN[7] + AnN[9] + AnN[11];" fullword ascii
    $s3  = "return sDADppw[0] + sDADppw[2] + sDADppw[4] + \".F\" + sDADppw[7] + sDADppw[9] + sDADppw[12] + sDADppw[14];" fullword ascii
    $s4  = "var sDADppw = clutw(gWIQxEORqA+\" \"+\"System Ni cSihM Obj quEFEy ect SFksgvk mtxIr\", \" \");" fullword ascii
    $s5  = "var AnN = (\"2.XMLHTTP MZRawOg LZwCU XML ream St lvNfgXUZ AD iVgfZiL O xGQB D\").split(\" \");" fullword ascii
    $s6  = "mZUz.open(CdWIh,sraXh,false);" fullword ascii
    $s7  = "IOF.CreateFolder(fIlm);" fullword ascii
    $s8  = "return WfTGTgB(TQ,GGtgR[298-292]+GGtgR[208-201]+GGtgR[699-691]);" fullword ascii
    $s9  = "function MPJE(DYmWg) {" fullword ascii
    $s10 = "return tsKLf.status;" fullword ascii
    $s11 = "return pQKTW;" fullword ascii
    $s12 = "function PiUa(cqmwd) {" fullword ascii
    $s13 = "if (SXuzD == 810-610){return true;} else {return false;}" fullword ascii
    $s14 = "return new ActiveXObject(BrcO);" fullword ascii
    $s15 = "HKx = D; break; " fullword ascii
    $s16 = "function clutw(bYs,gWYNZ) {" fullword ascii
    $s17 = "return ivSHkh/*EiJnzZVaG9GaFyI7nI30oyYqk*/.position=258-258;" fullword ascii
    $s18 = "function AOtztNVIM(QnXne) {" fullword ascii
    $s19 = "function ZpROYaJbV(LZDDXyZwUkK) {" fullword ascii
    $s20 = "function uyBf(EHmFZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}