rule sig_20160404_83b721ece76fae23e5652412be57816c {
  meta:
    description = "datamaliciousorder - file 20160404_83b721ece76fae23e5652412be57816c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58d7c45137635abe22a5217b32978ea64efd27d6bdba5c9ba4c479e1eae5436f"

  strings:
    $s1  = "return RxiGjee[0] + RxiGjee[2] + RxiGjee[4] + \".F\" + RxiGjee[7] + RxiGjee[9] + RxiGjee[12] + RxiGjee[14];" fullword ascii
    $s2  = "var gD = true  , TqBf = KFw[7] + KFw[9] + KFw[11];" fullword ascii
    $s3  = "var KFw = (\"2.XMLHTTP qLTUxjk EEtgz XML ream St iFkXTcSr AD PkyqpNB O moAy D\").split(\" \");" fullword ascii
    $s4  = "RrGP.open(uHhtP,EXxUk,false);" fullword ascii
    $s5  = "var RxiGjee = eDjnv(TJHcgmYNiq+\" \"+\"System th FFJMY Obj afuIgs ect kHfCFpU aAaFe\", \" \");" fullword ascii
    $s6  = "if (w >= oybFF.length) {break;}" fullword ascii
    $s7  = "function KaxSn(naWXrcgm,qqGW) {" fullword ascii
    $s8  = "function LgyomTP(GkgB,fPPgN) {" fullword ascii
    $s9  = "function RQjULHCI(tPx) {" fullword ascii
    $s10 = "return LgyomTP(uB,KApHO[164-158]+KApHO[419-412]+KApHO[858-850]);" fullword ascii
    $s11 = "function htuo(jpJxH) {" fullword ascii
    $s12 = "function vrRjuo(SyKMhSZ) {" fullword ascii
    $s13 = "function HVjE(czYGS,EXxUk,uHhtP) {" fullword ascii
    $s14 = "function vsPb(fvPvF) {" fullword ascii
    $s15 = "return BgsW[LqKkZR[0]];" fullword ascii
    $s16 = "if (TLdvz > 190629-256){return true;} else {return false;}" fullword ascii
    $s17 = "if(r>=m.length) {break;}" fullword ascii
    $s18 = "function iyKd(PqFdv) {" fullword ascii
    $s19 = "return fvPvF.status;" fullword ascii
    $s20 = "return Kni.split(IOZhD);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}