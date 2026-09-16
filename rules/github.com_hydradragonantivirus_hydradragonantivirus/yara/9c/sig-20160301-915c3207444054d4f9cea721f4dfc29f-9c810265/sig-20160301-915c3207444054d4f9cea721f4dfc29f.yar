rule sig_20160301_915c3207444054d4f9cea721f4dfc29f {
  meta:
    description = "datamaliciousorder - file 20160301_915c3207444054d4f9cea721f4dfc29f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "246216fc9a54ebe7a5321314d8c54c459a7472d1f2039ac96dfa82dbf66f1965"

  strings:
    $s1  = "var sf = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(BzXyH);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + dkNtHlH + \".F\" + CXcDVnXMuX + jVHIz + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var NXm = (gAT + \"TTP\" + \" BVyFNYI moVar XML ream St cYgdXMXD AD tzWzMIN OD\").split(\" \");" fullword ascii
    $s5  = "var Iz = true  , AXFF = NXm[7] + \"\" + NXm[9];" fullword ascii
    $s6  = "UrfDu.open(LXgoR,lCCHA,false);" fullword ascii
    $s7  = "function ZLNC(aZYXJ) {" fullword ascii
    $s8  = "function uJlDxADZz(zRCwA,yzzpd,UvvvI) {" fullword ascii
    $s9  = "function NUdo(BzXyH) {" fullword ascii
    $s10 = "function SixodvyQj(kAdBmQREcEz) {" fullword ascii
    $s11 = "if(E>=P.length) {break;}" fullword ascii
    $s12 = "function VBsM(UrfDu,lCCHA,LXgoR) {" fullword ascii
    $s13 = "vfr = E; break; " fullword ascii
    $s14 = "function EOoT(dwvdD) {" fullword ascii
    $s15 = "return oKHoj;" fullword ascii
    $s16 = "function iOxuMqSy() {" fullword ascii
    $s17 = "function powp(yhPvt,mmfBc) {" fullword ascii
    $s18 = "function eMBp(VAoeC) {" fullword ascii
    $s19 = "return GEFdb.status;" fullword ascii
    $s20 = "function rLnS(KdxSA,NDrsw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}