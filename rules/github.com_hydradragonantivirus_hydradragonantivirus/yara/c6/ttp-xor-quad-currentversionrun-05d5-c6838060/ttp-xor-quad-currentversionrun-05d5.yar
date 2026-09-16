rule TTP_XOR_QUAD_CurrentVersionRun_05d5 {
  strings:
    $key_05d5 = { 56 ba [2] 72 b4 [2] 59 98 [2] 77 ba [2] 63 a1 [2] 6c bb [2] 72 a6 [2] 70 a7 [2] 6b a1 [2] 77 a6 [2] 6b 89 }

  condition:
    any of them
}