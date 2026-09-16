rule TTP_XOR_QUAD_CurrentVersionRun_00d4 {
  strings:
    $key_00d4 = { 53 bb [2] 77 b5 [2] 5c 99 [2] 72 bb [2] 66 a0 [2] 69 ba [2] 77 a7 [2] 75 a6 [2] 6e a0 [2] 72 a7 [2] 6e 88 }

  condition:
    any of them
}