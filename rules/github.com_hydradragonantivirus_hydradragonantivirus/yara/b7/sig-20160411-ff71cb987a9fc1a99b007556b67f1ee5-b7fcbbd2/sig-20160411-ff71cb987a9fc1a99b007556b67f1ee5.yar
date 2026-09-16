rule sig_20160411_ff71cb987a9fc1a99b007556b67f1ee5 {
  meta:
    description = "datamaliciousorder - file 20160411_ff71cb987a9fc1a99b007556b67f1ee5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "466141dc86eb0e5faea910c8aecbd1cb5970b08296130efa3adddd1c9716f4b0"

  strings:
    $s1  = "var Zoa = (\"2.XMLHTTP MqgIcUS HGbWM XML ream St EuQmSIEH AD hHJKtXo O tZHc D\").split(\" \");" fullword ascii
    $s2  = "return UskoNTo[0] + UskoNTo[2] + UskoNTo[4] + \".F\" + UskoNTo[7] + UskoNTo[9] + UskoNTo[12] + UskoNTo[14];" fullword ascii
    $s3  = "var Se = true  , ZfPM = Zoa[7] + Zoa[9] + Zoa[11];" fullword ascii
    $s4  = "eRar.open(GcTXW,ovsEJ,false);" fullword ascii
    $s5  = "if(y>=t.length) {break;}" fullword ascii
    $s6  = "return YiUh[GyFIpcY[0]+GyFIpcY[1]];" fullword ascii
    $s7  = "function VKkYV(Mzh,UdlpA) {" fullword ascii
    $s8  = "return CtWAsMq(vM,PfZHbz+mrNIH[231-223]);" fullword ascii
    $s9  = "function SIhe(sRwjL) {" fullword ascii
    $s10 = "if (dzZRW > 177188-614){return true;} else {return false;}" fullword ascii
    $s11 = "return JimTq;" fullword ascii
    $s12 = "return aATCvS[bVXA[207-207]]=916-916;" fullword ascii
    $s13 = "function CtWAsMq(wRFn,DnwgV) {" fullword ascii
    $s14 = "if (sRwjL == 744-544){return true;} else {return false;}" fullword ascii
    $s15 = "function MCbEmKcx(SiPt) {" fullword ascii
    $s16 = "function lEEx(uXtpi) {" fullword ascii
    $s17 = "function xeeTgW(RBTn,hUyGUW) {" fullword ascii
    $s18 = "Gqf = y; break; " fullword ascii
    $s19 = "function zlEdteeY(pQW) {" fullword ascii
    $s20 = "function mKRGWISHb(FoRQt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}