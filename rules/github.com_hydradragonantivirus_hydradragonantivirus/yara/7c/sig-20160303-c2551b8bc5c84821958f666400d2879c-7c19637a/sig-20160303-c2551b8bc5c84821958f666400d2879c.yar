rule sig_20160303_c2551b8bc5c84821958f666400d2879c {
  meta:
    description = "datamaliciousorder - file 20160303_c2551b8bc5c84821958f666400d2879c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e63d7a722e2e1de1ee20260b7384e9a0fc2978ca1d82b1cb1d4ba88396c0225"

  strings:
    $s1  = "var TV = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "AWuDG.open(jhwpr,BLogP,false);" fullword ascii
    $s3  = "return WScript.CreateObject(NfXhO);" fullword ascii
    $s4  = "function Qjib(AWuDG,BLogP,jhwpr) {" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + RNszJxm + \".F\" + GAvOVNZdPq + uKGra + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "var Tp = true  , PnMp = Nrc[7] + \"\" + Nrc[9];" fullword ascii
    $s7  = "var Nrc = (ibp + \"TTP\" + \" eJLzbQR rFKyr XML ream St trRSihVv AD TfPuliT OD\").split(\" \");" fullword ascii
    $s8  = "function atFP(jCkHV) {" fullword ascii
    $s9  = "Hgj = x; break; " fullword ascii
    $s10 = "function yqyhKhABR(fvPjFCIANYc) {" fullword ascii
    $s11 = "function tJWH(KtMrA) {" fullword ascii
    $s12 = "if(x>=h.length) {break;}" fullword ascii
    $s13 = "return new ActiveXObject(rHZEfx);" fullword ascii
    $s14 = "function rbkT(gKdif) {" fullword ascii
    $s15 = "return yC.ExpandEnvironmentStrings(TV);" fullword ascii
    $s16 = "function QYQbL(rHZEfx) {" fullword ascii
    $s17 = "function vIxm(DyXSE,VBTFH) {" fullword ascii
    $s18 = "function PhZrMoClU(cRRIw,PoGPs,USjzn) {" fullword ascii
    $s19 = "function lHnR(gXJpn) {" fullword ascii
    $s20 = "function JfLx(teAlv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}