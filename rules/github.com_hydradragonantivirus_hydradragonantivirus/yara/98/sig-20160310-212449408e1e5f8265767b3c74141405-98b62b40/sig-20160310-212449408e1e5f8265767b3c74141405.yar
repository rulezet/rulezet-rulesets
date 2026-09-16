rule sig_20160310_212449408e1e5f8265767b3c74141405 {
  meta:
    description = "datamaliciousorder - file 20160310_212449408e1e5f8265767b3c74141405.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04fbcee4ee4bcb316caf4a403479592b4c402e4877b651c8e0fa4a2a5225ca1b"

  strings:
    $s1  = "var Pt = true  , aPCU = tku[7] + tku[9] + tku[11];" fullword ascii
    $s2  = "return kwTjWNm[0] + kwTjWNm[2] + kwTjWNm[4] + \".F\" + kwTjWNm[7] + kwTjWNm[9] + kwTjWNm[12] + kwTjWNm[14];" fullword ascii
    $s3  = "TepBr.open(IhxYE,SRIST,false);" fullword ascii
    $s4  = "var tku = (\"2.XMLHTTP PBfzHKR rrAaE XML ream St QWEOwBOJ AD qPBmUFR O mJVy D\").split(\" \");" fullword ascii
    $s5  = "var kwTjWNm = \"Sc TiLZfmX r uozdXdkEJ ipting rsAlDMd tpu ile MMvvIVBkooKgje System EN YDaxh Obj PCFNsM ect ychAAyM\".split(\" " ascii
    $s6  = "function fLwf(EqiFG) {" fullword ascii
    $s7  = "function fvXv(YKuXa,qslmx) {" fullword ascii
    $s8  = "function ymyU(wmPmZ) {" fullword ascii
    $s9  = "function ZMaLp(WLrWcY) {" fullword ascii
    $s10 = "function LXIOVPvV(yQImB,fflyBz) {" fullword ascii
    $s11 = "return HDYOvzx" fullword ascii
    $s12 = "function BTpx(LeJwx) {" fullword ascii
    $s13 = "return new ActiveXObject(WLrWcY);" fullword ascii
    $s14 = "function WSSF(AMFGt,jxxUu) {" fullword ascii
    $s15 = "function lmGCflH(kfMr,trNds) {" fullword ascii
    $s16 = "function BhYD(eSmoc) {" fullword ascii
    $s17 = "return nZJlGu.position=412-412;" fullword ascii
    $s18 = "function Tjjr(jarOc) {" fullword ascii
    $s19 = "if (wmPmZ > 158419-182){return true;} else {return false;}" fullword ascii
    $s20 = "if(O>=C.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}