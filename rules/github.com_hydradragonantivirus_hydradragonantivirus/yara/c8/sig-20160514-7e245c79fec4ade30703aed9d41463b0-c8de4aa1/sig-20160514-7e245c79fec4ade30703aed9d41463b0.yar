rule sig_20160514_7e245c79fec4ade30703aed9d41463b0 {
  meta:
    description = "datamaliciousorder - file 20160514_7e245c79fec4ade30703aed9d41463b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66b5769ddaa5ab5f98637d04a443f596b9ec9eec5352a5b15bf4277ee1a767ee"

  strings:
    $s1  = "var xGJhZ = SwIz + (9662 - 9661);" fullword ascii
    $s2  = "while (VOhByoB < cmptEm - (8652 + 2356 - 11006)) {" fullword ascii
    $s3  = "function Dbfof() {" fullword ascii
    $s4  = "return agVo;" fullword ascii
    $s5  = "function DGtZS() {" fullword ascii
    $s6  = "return KXqJzHCX;" fullword ascii
    $s7  = "function eAcyz() {" fullword ascii
    $s8  = "function BrSxthl() {" fullword ascii
    $s9  = "return cblhRAh;" fullword ascii
    $s10 = "function URXFTxA() {" fullword ascii
    $s11 = "nfliKX = true;" fullword ascii
    $s12 = "return eVKNx;" fullword ascii
    $s13 = "function qSeDZ() {" fullword ascii
    $s14 = "return XGkaWiaA;" fullword ascii
    $s15 = "function RveO(lBbj, FaeF) {" fullword ascii
    $s16 = "return DBOzJPa;" fullword ascii
    $s17 = "function JeEIG(GcbGxtg, jjwGNvU) {" fullword ascii
    $s18 = "function KgQEqG(dfegg) {" fullword ascii
    $s19 = "function CLA() {" fullword ascii
    $s20 = "function PEQ(GZkE, fDgn) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}