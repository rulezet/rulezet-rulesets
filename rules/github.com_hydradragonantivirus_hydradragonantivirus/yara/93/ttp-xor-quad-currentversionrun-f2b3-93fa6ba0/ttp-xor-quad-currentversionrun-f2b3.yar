rule TTP_XOR_QUAD_CurrentVersionRun_f2b3 {
  strings:
    $key_f2b3 = { a1 dc [2] 85 d2 [2] ae fe [2] 80 dc [2] 94 c7 [2] 9b dd [2] 85 c0 [2] 87 c1 [2] 9c c7 [2] 80 c0 [2] 9c ef }

  condition:
    any of them
}