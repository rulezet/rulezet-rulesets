rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_6ed03f6116d8_3488 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash3       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"

  strings:
    $s1 = "ion f000(){return \"ZGq\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "eturn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})()" ascii
    $s3 = "f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s4 = ",(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){r" ascii
    $s5 = "})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f00" ascii
    $s6 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}