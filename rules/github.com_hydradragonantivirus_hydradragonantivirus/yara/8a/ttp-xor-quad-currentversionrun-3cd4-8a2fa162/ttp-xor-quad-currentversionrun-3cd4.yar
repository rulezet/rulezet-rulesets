rule TTP_XOR_QUAD_CurrentVersionRun_3cd4 {
  strings:
    $key_3cd4 = { 6f bb [2] 4b b5 [2] 60 99 [2] 4e bb [2] 5a a0 [2] 55 ba [2] 4b a7 [2] 49 a6 [2] 52 a0 [2] 4e a7 [2] 52 88 }

  condition:
    any of them
}