rule TTP_XOR_QUAD_CurrentVersionRun_44d6 {
  strings:
    $key_44d6 = { 17 b9 [2] 33 b7 [2] 18 9b [2] 36 b9 [2] 22 a2 [2] 2d b8 [2] 33 a5 [2] 31 a4 [2] 2a a2 [2] 36 a5 [2] 2a 8a }

  condition:
    any of them
}