rule TTP_XOR_QUAD_CurrentVersionRun_39d4 {
  strings:
    $key_39d4 = { 6a bb [2] 4e b5 [2] 65 99 [2] 4b bb [2] 5f a0 [2] 50 ba [2] 4e a7 [2] 4c a6 [2] 57 a0 [2] 4b a7 [2] 57 88 }

  condition:
    any of them
}