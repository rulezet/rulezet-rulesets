rule TTP_XOR_QUAD_CurrentVersionRun_2ed4 {
  strings:
    $key_2ed4 = { 7d bb [2] 59 b5 [2] 72 99 [2] 5c bb [2] 48 a0 [2] 47 ba [2] 59 a7 [2] 5b a6 [2] 40 a0 [2] 5c a7 [2] 40 88 }

  condition:
    any of them
}