rule TTP_XOR_QUAD_CurrentVersionRun_6096 {
  strings:
    $key_6096 = { 33 f9 [2] 17 f7 [2] 3c db [2] 12 f9 [2] 06 e2 [2] 09 f8 [2] 17 e5 [2] 15 e4 [2] 0e e2 [2] 12 e5 [2] 0e ca }

  condition:
    any of them
}