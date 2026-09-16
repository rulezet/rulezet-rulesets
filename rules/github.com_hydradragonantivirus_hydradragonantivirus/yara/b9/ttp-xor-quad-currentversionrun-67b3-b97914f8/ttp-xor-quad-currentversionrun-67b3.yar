rule TTP_XOR_QUAD_CurrentVersionRun_67b3 {
  strings:
    $key_67b3 = { 34 dc [2] 10 d2 [2] 3b fe [2] 15 dc [2] 01 c7 [2] 0e dd [2] 10 c0 [2] 12 c1 [2] 09 c7 [2] 15 c0 [2] 09 ef }

  condition:
    any of them
}