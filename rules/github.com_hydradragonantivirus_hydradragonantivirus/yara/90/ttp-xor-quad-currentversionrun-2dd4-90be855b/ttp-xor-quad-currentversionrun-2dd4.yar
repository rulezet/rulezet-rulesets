rule TTP_XOR_QUAD_CurrentVersionRun_2dd4 {
  strings:
    $key_2dd4 = { 7e bb [2] 5a b5 [2] 71 99 [2] 5f bb [2] 4b a0 [2] 44 ba [2] 5a a7 [2] 58 a6 [2] 43 a0 [2] 5f a7 [2] 43 88 }

  condition:
    any of them
}