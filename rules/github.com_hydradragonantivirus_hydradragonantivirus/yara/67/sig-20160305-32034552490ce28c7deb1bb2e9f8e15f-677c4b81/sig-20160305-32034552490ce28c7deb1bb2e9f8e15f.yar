rule sig_20160305_32034552490ce28c7deb1bb2e9f8e15f {
  meta:
    description = "datamaliciousorder - file 20160305_32034552490ce28c7deb1bb2e9f8e15f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80bdb2d9e80388878d7a1e2782c9ca358eabc3394ef1d232f7e19e7f16ec815"

  strings:
    $s1  = "var JVnpQ = \"mZrnKT dVS pt.Shell KLlTkmS Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return jzAlIxx[0] + jzAlIxx[2] + jzAlIxx[4] + \".F\" + jzAlIxx[7] + jzAlIxx[9] + jzAlIxx[12] + jzAlIxx[14];" fullword ascii
    $s3  = "var Ap = true  , kctB = heE[7] + \"\" + heE[9];" fullword ascii
    $s4  = "var heE = (ZvX + \"TTP\" + \" EtBrsOf DvueS XML ream St cocyahnN AD kgBqjNo OD\").split(\" \");" fullword ascii
    $s5  = "var jzAlIxx = \"Sc VFDlpAn r gSiWnERzA ipting ylvTzUS afG ile IAKHDZdEQfYRYt System vc HYJKK Obj vfzImp ect hWQaIzY\".split(\" " ascii
    $s6  = "QuKAP.open(VyQfJ,IDTTn,false);" fullword ascii
    $s7  = "function stnv(TYStf,tEnKl) {" fullword ascii
    $s8  = "function IZRq(bwYCq,ghJXT) {" fullword ascii
    $s9  = "return new ActiveXObject(fIhXcS);" fullword ascii
    $s10 = "function hyHQrQil() {" fullword ascii
    $s11 = "function OlUwYfs(IhYJ) {" fullword ascii
    $s12 = "function cPrL(eNYCb) {" fullword ascii
    $s13 = "if (MOVcx > 166257-560){return true;} else {return false;}" fullword ascii
    $s14 = "function sNzc(BFvFB) {" fullword ascii
    $s15 = "function VhfC(Gobkb) {" fullword ascii
    $s16 = "return eNYCb.status;" fullword ascii
    $s17 = "if(T>=w.length) {break;}" fullword ascii
    $s18 = "function LwWCjRy(CKHq) {" fullword ascii
    $s19 = "function LwVA(jCrUt) {" fullword ascii
    $s20 = "function jOJD(JaJWf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}