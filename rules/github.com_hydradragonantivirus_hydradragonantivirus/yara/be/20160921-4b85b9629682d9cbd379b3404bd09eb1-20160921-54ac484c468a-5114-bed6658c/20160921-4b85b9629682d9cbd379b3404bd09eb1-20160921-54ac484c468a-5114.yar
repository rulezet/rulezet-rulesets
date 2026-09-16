rule _20160921_4b85b9629682d9cbd379b3404bd09eb1_20160921_54ac484c468a_5114 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash2       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash3       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"

  strings:
    $s1 = "return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(" ascii
    $s2 = "ion f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return " ascii
    $s3 = "unction f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){ret" ascii
    $s4 = "e\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function " ascii
    $s5 = " \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}