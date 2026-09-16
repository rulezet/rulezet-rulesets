rule _20160921_7f829eb25609c6f6d37ef18f9c4f8ad7_20160921_cf2bd9606d39_3064 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = "tion f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return" ascii
    $s2 = "rn \"BQb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s3 = "on f000(){return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s4 = "000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt" ascii
    $s5 = "){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(" ascii
    $s6 = "\"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Wy\";})(),(functi" ascii
    $s7 = "n\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}