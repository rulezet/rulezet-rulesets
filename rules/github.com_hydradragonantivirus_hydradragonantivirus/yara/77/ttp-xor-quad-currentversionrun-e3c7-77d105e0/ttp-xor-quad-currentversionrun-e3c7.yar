rule TTP_XOR_QUAD_CurrentVersionRun_e3c7 {
  strings:
    $key_e3c7 = { b0 a8 [2] 94 a6 [2] bf 8a [2] 91 a8 [2] 85 b3 [2] 8a a9 [2] 94 b4 [2] 96 b5 [2] 8d b3 [2] 91 b4 [2] 8d 9b }

  condition:
    any of them
}