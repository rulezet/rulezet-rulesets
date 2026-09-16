rule TTP_XOR_QUAD_CurrentVersionRun_1ec9 {
  strings:
    $key_1ec9 = { 4d a6 [2] 69 a8 [2] 42 84 [2] 6c a6 [2] 78 bd [2] 77 a7 [2] 69 ba [2] 6b bb [2] 70 bd [2] 6c ba [2] 70 95 }

  condition:
    any of them
}