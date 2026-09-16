rule TTP_XOR_QUAD_CurrentVersionRun_1dd4 {
  strings:
    $key_1dd4 = { 4e bb [2] 6a b5 [2] 41 99 [2] 6f bb [2] 7b a0 [2] 74 ba [2] 6a a7 [2] 68 a6 [2] 73 a0 [2] 6f a7 [2] 73 88 }

  condition:
    any of them
}