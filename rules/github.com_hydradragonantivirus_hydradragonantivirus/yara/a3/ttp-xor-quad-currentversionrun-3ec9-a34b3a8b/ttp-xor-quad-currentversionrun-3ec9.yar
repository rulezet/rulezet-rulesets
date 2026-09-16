rule TTP_XOR_QUAD_CurrentVersionRun_3ec9 {
  strings:
    $key_3ec9 = { 6d a6 [2] 49 a8 [2] 62 84 [2] 4c a6 [2] 58 bd [2] 57 a7 [2] 49 ba [2] 4b bb [2] 50 bd [2] 4c ba [2] 50 95 }

  condition:
    any of them
}