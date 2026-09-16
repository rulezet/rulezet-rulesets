rule TTP_XOR_QUAD_CurrentVersionRun_25d5 {
  strings:
    $key_25d5 = { 76 ba [2] 52 b4 [2] 79 98 [2] 57 ba [2] 43 a1 [2] 4c bb [2] 52 a6 [2] 50 a7 [2] 4b a1 [2] 57 a6 [2] 4b 89 }

  condition:
    any of them
}