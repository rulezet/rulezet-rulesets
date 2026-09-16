rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_1f7d568f432a_4310 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"

  strings:
    $s1 = "n \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s2 = "),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s3 = "0(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";" ascii
    $s4 = " f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Y" ascii
    $s5 = ",(function f000(){return \"Uo\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}