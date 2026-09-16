rule TTP_XOR_QUAD_CurrentVersionRun_24d4 {
  strings:
    $key_24d4 = { 77 bb [2] 53 b5 [2] 78 99 [2] 56 bb [2] 42 a0 [2] 4d ba [2] 53 a7 [2] 51 a6 [2] 4a a0 [2] 56 a7 [2] 4a 88 }

  condition:
    any of them
}