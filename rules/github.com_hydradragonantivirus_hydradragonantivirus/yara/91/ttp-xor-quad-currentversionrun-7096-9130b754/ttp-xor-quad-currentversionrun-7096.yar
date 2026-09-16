rule TTP_XOR_QUAD_CurrentVersionRun_7096 {
  strings:
    $key_7096 = { 23 f9 [2] 07 f7 [2] 2c db [2] 02 f9 [2] 16 e2 [2] 19 f8 [2] 07 e5 [2] 05 e4 [2] 1e e2 [2] 02 e5 [2] 1e ca }

  condition:
    any of them
}