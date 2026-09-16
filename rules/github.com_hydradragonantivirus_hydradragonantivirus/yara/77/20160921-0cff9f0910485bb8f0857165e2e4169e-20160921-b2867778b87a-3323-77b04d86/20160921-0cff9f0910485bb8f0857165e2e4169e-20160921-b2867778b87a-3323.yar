rule _20160921_0cff9f0910485bb8f0857165e2e4169e_20160921_b2867778b87a_3323 {
  meta:
    description = "datamaliciousorder - from files 20160921_0cff9f0910485bb8f0857165e2e4169e.js, 20160921_b2867778b87ab68774c77840f21eaed0.js, 20160921_dc8499faf06c485edd1ddc8df3a39f1c.js, 20160921_f75fc7d6e5f9a9e633ed6b173201a2a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dbe3dcf31ef6a75ca25b690245a2ec8ebd1f75d9a20a2b5dac46791b6ad354f"
    hash2       = "ae46b7285b241d53af42d1248b27d7d1186f12901d6fc0284d48665a3b217777"
    hash3       = "f991a0c08a08712da63725a1264034411c38050f80181edfb6cee6760198ffd6"
    hash4       = "b78b074fdbad3a2d311b3fe1363fedad42cd9a804cba11641844abee41e9ad5f"

  strings:
    $s1 = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"XTn" ascii
    $s2 = "eturn \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DYs\";})()" ascii
    $s3 = "unction f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"SGs\";})(),(function f000(){retu" ascii
    $s4 = "rn \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s5 = "00(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qz" ascii
    $s6 = "f000(){return \"Wh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}