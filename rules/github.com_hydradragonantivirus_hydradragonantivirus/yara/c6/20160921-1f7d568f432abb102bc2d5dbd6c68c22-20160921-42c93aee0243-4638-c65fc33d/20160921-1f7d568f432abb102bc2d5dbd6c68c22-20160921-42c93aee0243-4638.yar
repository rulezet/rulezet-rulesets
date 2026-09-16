rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_42c93aee0243_4638 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_42c93aee0243f217ab1a00a402ced889.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"

  strings:
    $s1 = "ion f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s2 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NYh\";}" ascii
    $s3 = "){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(" ascii
    $s4 = "f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KX" ascii
    $s5 = "(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}