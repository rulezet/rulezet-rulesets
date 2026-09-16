rule _20160921_975c5c13ffec0e2608898a142a2baed7_20160921_f1cc02f48879_3097 {
  meta:
    description = "datamaliciousorder - from files 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_f1cc02f488792b7161849f8d15549315.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash2       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"
    hash3       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "n \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(func" ascii
    $s2 = "unction f000(){return \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){retu" ascii
    $s3 = "00(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"DIa" ascii
    $s4 = " f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s5 = ";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function f00" ascii
    $s6 = "nction f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(function f000(){retu" ascii
    $s7 = "urn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"RPt\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}