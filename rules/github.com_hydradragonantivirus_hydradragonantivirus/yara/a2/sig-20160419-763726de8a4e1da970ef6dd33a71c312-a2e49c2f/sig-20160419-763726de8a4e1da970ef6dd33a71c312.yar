rule sig_20160419_763726de8a4e1da970ef6dd33a71c312 {
  meta:
    description = "datamaliciousorder - file 20160419_763726de8a4e1da970ef6dd33a71c312.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91196fc5d3383e5af23825be3594fe206e7e01934d6ed45e747d87b8027c0c9e"

  strings:
    $s1  = "var Nz = true  , yvun = jLS[7] + jLS[9] + jLS[11];" fullword ascii
    $s2  = "return ZhjzkJs[0] + ZhjzkJs[2] + ZhjzkJs[4] + \".F\" + ZhjzkJs[7] + ZhjzkJs[9] + ZhjzkJs[12] + ZhjzkJs[14];" fullword ascii
    $s3  = "var jLS = (\"2.XMLHTTP vUmJDNQ yxqNm XML ream St iyZFmktd AD IDvQjMD O cckn D\").split(\" \");" fullword ascii
    $s4  = "nXTS.open(leHRc,NoHor,false);" fullword ascii
    $s5  = "function yNzEAde(BmZL) {" fullword ascii
    $s6  = "function iUeYA(RPe,VynuX) {" fullword ascii
    $s7  = "function Nyzs(qrtjS) {" fullword ascii
    $s8  = "function FnFmO(SeYpFM) {" fullword ascii
    $s9  = "if(i>=z.length) {break;}" fullword ascii
    $s10 = "function bomjuw(gIMA,pEDpev) {" fullword ascii
    $s11 = "if (LSGqZ != 404-204){return false;} else {return true;}" fullword ascii
    $s12 = "function RvKD(lNqyN,JiBOa) {" fullword ascii
    $s13 = "function umYdmSyd(RJT) {" fullword ascii
    $s14 = "function HxgjA(qivHnDGv,DTsl) {" fullword ascii
    $s15 = "function NrOBZrX(LpEo,cXZoD) {" fullword ascii
    $s16 = "return RPe[kRcT[0]](VynuX);" fullword ascii
    $s17 = "function knDVIWvNZ(lVQFOXaqOzR) {" fullword ascii
    $s18 = "function knoi(yMFHa) {" fullword ascii
    $s19 = "function wuPj(lUgtj) {" fullword ascii
    $s20 = "Kfn = i; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}