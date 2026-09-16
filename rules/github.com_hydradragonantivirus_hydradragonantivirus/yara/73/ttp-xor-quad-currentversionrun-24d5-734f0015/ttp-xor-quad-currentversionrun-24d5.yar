rule TTP_XOR_QUAD_CurrentVersionRun_24d5 {
  strings:
    $key_24d5 = { 77 ba [2] 53 b4 [2] 78 98 [2] 56 ba [2] 42 a1 [2] 4d bb [2] 53 a6 [2] 51 a7 [2] 4a a1 [2] 56 a6 [2] 4a 89 }

  condition:
    any of them
}