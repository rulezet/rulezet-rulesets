rule TTP_XOR_QUAD_CurrentVersionRun_2cd4 {
  strings:
    $key_2cd4 = { 7f bb [2] 5b b5 [2] 70 99 [2] 5e bb [2] 4a a0 [2] 45 ba [2] 5b a7 [2] 59 a6 [2] 42 a0 [2] 5e a7 [2] 42 88 }

  condition:
    any of them
}