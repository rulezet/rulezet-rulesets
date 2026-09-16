rule _20160921_02b826231ece268e91633311d2c70554_20160921_63def3fff7f1_4144 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"

  strings:
    $s1 = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"XTn\";})(),(function f000()" ascii
    $s2 = " \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s3 = "n \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s4 = "tion f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s5 = "function f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}