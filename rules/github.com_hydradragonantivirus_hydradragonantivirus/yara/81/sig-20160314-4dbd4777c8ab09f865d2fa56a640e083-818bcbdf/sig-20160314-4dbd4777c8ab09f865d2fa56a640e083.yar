rule sig_20160314_4dbd4777c8ab09f865d2fa56a640e083 {
  meta:
    description = "datamaliciousorder - file 20160314_4dbd4777c8ab09f865d2fa56a640e083.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d387b668c0b08039faf26b7714ab00073a178a3b308558206870609fa8088bee"

  strings:
    $s1  = "return bTUYAKL[0] + bTUYAKL[2] + bTUYAKL[4] + \".F\" + bTUYAKL[7] + bTUYAKL[9] + bTUYAKL[12] + bTUYAKL[14];" fullword ascii
    $s2  = "var Ba = true  , xIrV = xeB[7] + xeB[9] + xeB[11];" fullword ascii
    $s3  = "VcwAn.open(KpIzp,BepIh,false);" fullword ascii
    $s4  = "var xeB = (\"2.XMLHTTP BXDTrzK QDJcL XML ream St bQJbVLCR AD tSczLWz O VPYQ D\").split(\" \");" fullword ascii
    $s5  = "function eBuP(BjYQD) {" fullword ascii
    $s6  = "function OdCi(qEPir) {" fullword ascii
    $s7  = "function jgYP(DhCjv) {" fullword ascii
    $s8  = "return GKhYb;" fullword ascii
    $s9  = "function psgVqZYL() {" fullword ascii
    $s10 = "return OBIVjTl" fullword ascii
    $s11 = "function dREh(ROTYv) {" fullword ascii
    $s12 = "if (ByuLW > 176668-102){return true;} else {return false;}" fullword ascii
    $s13 = "return BjYQD.status;" fullword ascii
    $s14 = "if(E>=q.length) {break;}" fullword ascii
    $s15 = "return njWphXG(NM,CzObW[397-391]+CzObW[275-268]+CzObW[441-433]);" fullword ascii
    $s16 = "function jDdP(VcwAn,BepIh,KpIzp) {" fullword ascii
    $s17 = "return yBAT.ExpandEnvironmentStrings(ncQmN);" fullword ascii
    $s18 = "function USQrv(cInzla) {" fullword ascii
    $s19 = "if (L >= qEPir.length) {break;}" fullword ascii
    $s20 = "function SWAaiQTpf(mgrrxkYTglR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}