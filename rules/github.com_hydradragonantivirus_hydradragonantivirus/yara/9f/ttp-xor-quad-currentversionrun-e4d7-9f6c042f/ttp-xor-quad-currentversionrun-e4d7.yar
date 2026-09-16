rule TTP_XOR_QUAD_CurrentVersionRun_e4d7 {
  strings:
    $key_e4d7 = { b7 b8 [2] 93 b6 [2] b8 9a [2] 96 b8 [2] 82 a3 [2] 8d b9 [2] 93 a4 [2] 91 a5 [2] 8a a3 [2] 96 a4 [2] 8a 8b }

  condition:
    any of them
}