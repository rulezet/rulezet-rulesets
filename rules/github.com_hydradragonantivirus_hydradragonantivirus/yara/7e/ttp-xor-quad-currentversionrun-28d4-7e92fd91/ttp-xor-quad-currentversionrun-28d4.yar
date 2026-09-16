rule TTP_XOR_QUAD_CurrentVersionRun_28d4 {
  strings:
    $key_28d4 = { 7b bb [2] 5f b5 [2] 74 99 [2] 5a bb [2] 4e a0 [2] 41 ba [2] 5f a7 [2] 5d a6 [2] 46 a0 [2] 5a a7 [2] 46 88 }

  condition:
    any of them
}