rule TTP_XOR_QUAD_CurrentVersionRun_4dd4 {
  strings:
    $key_4dd4 = { 1e bb [2] 3a b5 [2] 11 99 [2] 3f bb [2] 2b a0 [2] 24 ba [2] 3a a7 [2] 38 a6 [2] 23 a0 [2] 3f a7 [2] 23 88 }

  condition:
    any of them
}