rule sig_20170116_8a698d85797d59c1965997718b070c25 {
  meta:
    description = "datamaliciousorder - file 20170116_8a698d85797d59c1965997718b070c25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d49cc922a4fff601a5d65d82338a03fdc8601c12d9dbded9d1763c10af83f611"

  strings:
    $x1  = "var n55 = new Array(); function z24(s54) { return s54; }; n55[429] = z24('fp.W', 25, 41); function v29(k40) { return k40; }; n55" ascii
    $s2  = "'.txt\")', 70); function c13(r70) { return r70; }; n55[857] = c13('C% /c ', 2, 7); function s27(p79) { return p79; }; n55[126] =" ascii
    $s3  = "unction e49(l24) { return l24; }; n55[47] = e49('o.com', 8); function j98(e14) { return e14; }; n55[124] = j98('m\"); v', 7, 22," ascii
    $s4  = "m89(w53) { return w53; }; n55[588] = m89('p.', 75, 75, 32); function e78(n35) { return n35; }; n55[45] = e78('p.com\"', 55, 43);" ascii
    $s5  = "843] = s47('\"+cs+\"', 19, 53); function x15(b54) { return b54; }; n55[612] = x15(' - N', 56, 39); function f40(v38) { return v3" ascii
    $s6  = "= t23('D \"', 68); function n92(c28) { return c28; }; n55[651] = n92('  - Yo', 98); function c48(h94) { return h94; }; n55[527] " ascii
    $s7  = "}; n55[628] = s14(' - It', 36, 52, 2); function b49(m74) { return m74; }; n55[359] = b49('p.Writ', 41, 5, 57); function a38(t60)" ascii
    $s8  = "88); function b84(h99) { return h99; }; n55[693] = b84('% /c ', 22, 13); function g26(u14) { return u14; }; n55[233] = g26('=3){" ascii
    $s9  = " n55[847] = o88('cs+\"', 78); function x34(e37) { return e37; }; n55[593] = x34('  - I', 34); function s61(m37) { return m37; };" ascii
    $s10 = " return p92; }; n55[750] = a77(' /t R', 60, 84, 100); function d10(z85) { return z85; }; n55[135] = d10('temO', 49, 24); functio" ascii
    $s11 = "n54(e52) { return e52; }; n55[280] = n54('\".exe', 63, 68, 50); function l87(q84) { return q84; }; n55[770] = l87('ypt', 9); fun" ascii
    $s12 = "; n55[379] = g81('Lin', 59); function s18(p41) { return p41; }; n55[859] = s18('.exe \"', 46, 80, 44); function t78(x70) { retur" ascii
    $s13 = "5[96] = z53('\"%TEMP', 99); function t95(m34) { return m34; }; n55[19] = t95('fromCh', 63, 59); function w42(p57) { return p57; " ascii
    $s14 = "55[596] = k14(' not', 38); function v48(q23) { return q23; }; n55[802] = v48('.Run(\"', 62, 93); function s14(y91) { return y91;" ascii
    $s15 = "urn a63; }; n55[52] = v63('obr', 72, 68); function j43(q10) { return q10; }; n55[827] = j43('.Run(\"', 55); function z34(v45) { " ascii
    $s16 = " x46(e56) { return e56; }; n55[386] = x46('ual:\")', 71, 13, 80); function w14(s15) { return s15; }; n55[683] = w14('PT.t', 70, " ascii
    $s17 = "rn c56; }; n55[760] = z38('.Run(', 59); function r91(j29) { return j29; }; n55[450] = r91('iteLi', 53); function i68(k34) { retu" ascii
    $s18 = "unction g59(t16) { return t16; }; n55[582] = g59('R:\")', 4, 11, 5); function w36(m27) { return m27; }; n55[243] = w36('){xa', 5" ascii
    $s19 = "on k83(i92) { return i92; }; n55[854] = k83('ws.Run', 76, 54); function r73(o79) { return o79; }; n55[426] = r73('teLi', 59, 85)" ascii
    $s20 = ") { return v60; }; n55[31] = b90('ar', 83, 65); function y11(m38) { return m38; }; n55[688] = y11('.Run(\"', 77, 69, 75); functi" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}