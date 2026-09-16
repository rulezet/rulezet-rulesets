rule _20160921_b7400937fc4eb76c7ea3adaa321d7619_20160921_ba8a9f239804_5654 {
  meta:
    description = "datamaliciousorder - from files 20160921_b7400937fc4eb76c7ea3adaa321d7619.js, 20160921_ba8a9f239804499b5d1d2a06a862c1ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"
    hash2       = "4ab28724a794acc5764f2e51f93d2b91ef9513b43e4cb9b0d10bad2710c2e6d7"

  strings:
    $s1 = "){return \"Lp\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(" ascii
    $s2 = "tion f000(){return \"KDh\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s3 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii
    $s4 = "j\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Vj\";})(),(function " ascii
    $s5 = "){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}