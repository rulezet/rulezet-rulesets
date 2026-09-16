rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_78bd4256ddc0_4655 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"

  strings:
    $s1 = "g\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s2 = "fuck(){return \"Wo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Fv" ascii
    $s3 = "turn \"Dc\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Pc\";})(),(f" ascii
    $s4 = "w\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";})(),(function " ascii
    $s5 = "ction fuck(){return \"Bz\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}