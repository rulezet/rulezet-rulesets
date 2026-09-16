rule _20160921_27fb26e7e153703634890a2f9e37ef7b_20160921_3e524aa8d0a1_3554 {
  meta:
    description = "datamaliciousorder - from files 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash2       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash3       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1 = "n \"Yv\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s2 = "0(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Zj\";}" ascii
    $s3 = "ion f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s4 = "urn \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Mt\";})(),(f" ascii
    $s5 = ",(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(function f000(){" ascii
    $s6 = "f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PT" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}