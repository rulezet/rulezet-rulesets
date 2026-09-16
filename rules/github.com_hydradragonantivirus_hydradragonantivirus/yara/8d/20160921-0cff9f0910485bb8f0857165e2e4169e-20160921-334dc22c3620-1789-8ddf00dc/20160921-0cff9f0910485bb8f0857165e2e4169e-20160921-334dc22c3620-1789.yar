rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_334dc22c3620_1789 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash3       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash4       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1  = "0(){return \"DYs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";" ascii
    $s2  = "n f000(){return \"HJm\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s3  = "t\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s4  = "ction f000(){return \"Br\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s5  = "n\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s6  = "0(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb\"" ascii
    $s7  = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\"" ascii
    $s8  = "Eo\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s9  = " f000(){return \"DYx\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s10 = "eturn \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}