rule TTP_XOR_QUAD_CurrentVersionRun_05d4 {
  strings:
    $key_05d4 = { 56 bb [2] 72 b5 [2] 59 99 [2] 77 bb [2] 63 a0 [2] 6c ba [2] 72 a7 [2] 70 a6 [2] 6b a0 [2] 77 a7 [2] 6b 88 }

  condition:
    any of them
}