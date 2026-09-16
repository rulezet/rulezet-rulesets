rule _20160921_02b826231ece268e91633311d2c70554_20160921_46b3ab412369_4136 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash3       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash4       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"

  strings:
    $s1 = "n f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Z" ascii
    $s2 = "n \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s3 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"S" ascii
    $s4 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"UE" ascii
    $s5 = "n \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}