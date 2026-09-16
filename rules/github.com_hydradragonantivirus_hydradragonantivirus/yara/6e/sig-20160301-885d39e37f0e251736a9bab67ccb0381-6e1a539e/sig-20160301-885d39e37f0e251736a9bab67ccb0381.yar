rule sig_20160301_885d39e37f0e251736a9bab67ccb0381 {
  meta:
    description = "datamaliciousorder - file 20160301_885d39e37f0e251736a9bab67ccb0381.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a6ea5ee1abc116ee360bf1878bb96adea1c560e998fc4f4a5d3a85321de87ea"

  strings:
    $s1  = "var rj = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(ZqzQW);" fullword ascii
    $s3  = "var jb = true  , vDwG = kNk[7] + \"\" + kNk[9];" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + OCkYVMU + \".F\" + FjTbMoVNTj + HAHpX + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var kNk = (ban + \"TTP\" + \" pDvBWaO mJafZ XML ream St qzDRnMaD AD FDioYaY OD\").split(\" \");" fullword ascii
    $s6  = "function lebbRERnG(EyYYYXFBKkO) {" fullword ascii
    $s7  = "FzAGN.open(DthRJ,pcUlt,false);" fullword ascii
    $s8  = "function dhFg(neweh) {" fullword ascii
    $s9  = "function boVd(iwVyd,ekZTV) {" fullword ascii
    $s10 = "function bYBF(IHKSZ,mBdxc) {" fullword ascii
    $s11 = "return BRYxN;" fullword ascii
    $s12 = "function lgQU(Egobg) {" fullword ascii
    $s13 = "function HHYimYMl() {" fullword ascii
    $s14 = "function pbFRK(BrLFfO) {" fullword ascii
    $s15 = "function SoEU(HYWMi) {" fullword ascii
    $s16 = "if(X>=J.length) {break;}" fullword ascii
    $s17 = "function HxhU(ZyKuy) {" fullword ascii
    $s18 = "return OuJDV.status;" fullword ascii
    $s19 = "function wDNP(VaGYS) {" fullword ascii
    $s20 = "function UUDc(OuJDV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}