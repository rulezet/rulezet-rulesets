rule TTP_XOR_QUAD_CurrentVersionRun_08d4 {
  strings:
    $key_08d4 = { 5b bb [2] 7f b5 [2] 54 99 [2] 7a bb [2] 6e a0 [2] 61 ba [2] 7f a7 [2] 7d a6 [2] 66 a0 [2] 7a a7 [2] 66 88 }

  condition:
    any of them
}