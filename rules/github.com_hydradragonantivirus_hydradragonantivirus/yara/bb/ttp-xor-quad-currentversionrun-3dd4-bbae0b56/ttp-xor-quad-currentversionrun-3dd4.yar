rule TTP_XOR_QUAD_CurrentVersionRun_3dd4 {
  strings:
    $key_3dd4 = { 6e bb [2] 4a b5 [2] 61 99 [2] 4f bb [2] 5b a0 [2] 54 ba [2] 4a a7 [2] 48 a6 [2] 53 a0 [2] 4f a7 [2] 53 88 }

  condition:
    any of them
}