rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_54ac484c468a_2247 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash3       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash4       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1 = "(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wh\";})(),(function f000(){ret" ascii
    $s2 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"DAp\";})(),(fu" ascii
    $s3 = "Bs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s4 = "00(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lo\"" ascii
    $s5 = "Br\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Rh\";})(),(functio" ascii
    $s6 = "ction f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"DYx\";})(),(function f000(){retur" ascii
    $s7 = "00(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\";" ascii
    $s8 = "GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qj\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}