rule TTP_XOR_QUAD_CurrentVersionRun_f3b3 {
  strings:
    $key_f3b3 = { a0 dc [2] 84 d2 [2] af fe [2] 81 dc [2] 95 c7 [2] 9a dd [2] 84 c0 [2] 86 c1 [2] 9d c7 [2] 81 c0 [2] 9d ef }

  condition:
    any of them
}