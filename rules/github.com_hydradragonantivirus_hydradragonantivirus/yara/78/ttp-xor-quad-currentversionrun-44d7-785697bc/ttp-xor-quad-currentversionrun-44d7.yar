rule TTP_XOR_QUAD_CurrentVersionRun_44d7 {
  strings:
    $key_44d7 = { 17 b8 [2] 33 b6 [2] 18 9a [2] 36 b8 [2] 22 a3 [2] 2d b9 [2] 33 a4 [2] 31 a5 [2] 2a a3 [2] 36 a4 [2] 2a 8b }

  condition:
    any of them
}