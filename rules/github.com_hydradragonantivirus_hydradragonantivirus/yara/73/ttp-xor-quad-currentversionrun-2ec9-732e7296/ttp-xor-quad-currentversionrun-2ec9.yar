rule TTP_XOR_QUAD_CurrentVersionRun_2ec9 {
  strings:
    $key_2ec9 = { 7d a6 [2] 59 a8 [2] 72 84 [2] 5c a6 [2] 48 bd [2] 47 a7 [2] 59 ba [2] 5b bb [2] 40 bd [2] 5c ba [2] 40 95 }

  condition:
    any of them
}