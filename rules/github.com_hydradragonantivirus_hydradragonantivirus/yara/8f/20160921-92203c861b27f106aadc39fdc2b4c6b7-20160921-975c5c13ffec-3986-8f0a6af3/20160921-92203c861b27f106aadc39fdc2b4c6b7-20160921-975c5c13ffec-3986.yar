rule _20160921_92203c861b27f106aadc39fdc2b4c6b7_20160921_975c5c13ffec_3986 {
  meta:
    description = "datamaliciousorder - from files 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash2       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash3       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash4       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "unction f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s2 = "{return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})" ascii
    $s3 = " \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s4 = "000(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn" ascii
    $s5 = "eturn \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})()" ascii
    $s6 = "n \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}