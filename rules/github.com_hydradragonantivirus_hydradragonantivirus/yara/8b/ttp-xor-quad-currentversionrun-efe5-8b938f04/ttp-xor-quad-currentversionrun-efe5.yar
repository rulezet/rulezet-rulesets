rule TTP_XOR_QUAD_CurrentVersionRun_efe5 {
  strings:
    $key_efe5 = { bc 8a [2] 98 84 [2] b3 a8 [2] 9d 8a [2] 89 91 [2] 86 8b [2] 98 96 [2] 9a 97 [2] 81 91 [2] 9d 96 [2] 81 b9 }

  condition:
    any of them
}