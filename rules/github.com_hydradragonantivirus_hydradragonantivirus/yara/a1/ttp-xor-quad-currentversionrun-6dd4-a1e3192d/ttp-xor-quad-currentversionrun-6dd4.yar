rule TTP_XOR_QUAD_CurrentVersionRun_6dd4 {
  strings:
    $key_6dd4 = { 3e bb [2] 1a b5 [2] 31 99 [2] 1f bb [2] 0b a0 [2] 04 ba [2] 1a a7 [2] 18 a6 [2] 03 a0 [2] 1f a7 [2] 03 88 }

  condition:
    any of them
}