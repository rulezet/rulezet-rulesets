rule TTP_XOR_QUAD_CurrentVersionRun_e7b3 {
  strings:
    $key_e7b3 = { b4 dc [2] 90 d2 [2] bb fe [2] 95 dc [2] 81 c7 [2] 8e dd [2] 90 c0 [2] 92 c1 [2] 89 c7 [2] 95 c0 [2] 89 ef }

  condition:
    any of them
}