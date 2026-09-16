rule TTP_XOR_QUAD_CurrentVersionRun_77b3 {
  strings:
    $key_77b3 = { 24 dc [2] 00 d2 [2] 2b fe [2] 05 dc [2] 11 c7 [2] 1e dd [2] 00 c0 [2] 02 c1 [2] 19 c7 [2] 05 c0 [2] 19 ef }

  condition:
    any of them
}