rule _20160921_a65ac281dbfddbf6dbe63a0288de8c70_20160921_aa105be6eeb7_5607 {
  meta:
    description = "datamaliciousorder - from files 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash2       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash3       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1 = "(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Mt\";})(),(function f000(){ret" ascii
    $s2 = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return " ascii
    $s3 = " f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"D" ascii
    $s4 = "00(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz" ascii
    $s5 = "f000(){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"O" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}