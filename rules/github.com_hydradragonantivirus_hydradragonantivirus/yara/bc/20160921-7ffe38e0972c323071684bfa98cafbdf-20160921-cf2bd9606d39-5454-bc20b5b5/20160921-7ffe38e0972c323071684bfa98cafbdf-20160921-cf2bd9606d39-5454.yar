rule _20160921_7ffe38e0972c323071684bfa98cafbdf_20160921_cf2bd9606d39_5454 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ffe38e0972c323071684bfa98cafbdf.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = ")(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s2 = "f000(){return \"Wy\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QD" ascii
    $s3 = "eturn \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(" ascii
    $s4 = ";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s5 = "n\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}