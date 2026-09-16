rule TTP_XOR_QUAD_CurrentVersionRun_30d4 {
  strings:
    $key_30d4 = { 63 bb [2] 47 b5 [2] 6c 99 [2] 42 bb [2] 56 a0 [2] 59 ba [2] 47 a7 [2] 45 a6 [2] 5e a0 [2] 42 a7 [2] 5e 88 }

  condition:
    any of them
}