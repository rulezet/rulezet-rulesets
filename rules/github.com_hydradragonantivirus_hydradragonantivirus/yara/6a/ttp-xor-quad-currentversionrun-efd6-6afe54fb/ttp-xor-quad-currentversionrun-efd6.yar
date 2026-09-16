rule TTP_XOR_QUAD_CurrentVersionRun_efd6 {
  strings:
    $key_efd6 = { bc b9 [2] 98 b7 [2] b3 9b [2] 9d b9 [2] 89 a2 [2] 86 b8 [2] 98 a5 [2] 9a a4 [2] 81 a2 [2] 9d a5 [2] 81 8a }

  condition:
    any of them
}