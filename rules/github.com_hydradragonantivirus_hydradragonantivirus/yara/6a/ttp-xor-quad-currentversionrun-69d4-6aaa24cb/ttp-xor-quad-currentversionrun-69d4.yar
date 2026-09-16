rule TTP_XOR_QUAD_CurrentVersionRun_69d4 {
  strings:
    $key_69d4 = { 3a bb [2] 1e b5 [2] 35 99 [2] 1b bb [2] 0f a0 [2] 00 ba [2] 1e a7 [2] 1c a6 [2] 07 a0 [2] 1b a7 [2] 07 88 }

  condition:
    any of them
}