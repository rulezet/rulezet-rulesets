rule TTP_XOR_QUAD_CurrentVersionRun_6cd4 {
  strings:
    $key_6cd4 = { 3f bb [2] 1b b5 [2] 30 99 [2] 1e bb [2] 0a a0 [2] 05 ba [2] 1b a7 [2] 19 a6 [2] 02 a0 [2] 1e a7 [2] 02 88 }

  condition:
    any of them
}