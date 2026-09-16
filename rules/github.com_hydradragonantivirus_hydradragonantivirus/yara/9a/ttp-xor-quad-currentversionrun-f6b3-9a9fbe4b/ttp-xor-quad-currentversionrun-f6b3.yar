rule TTP_XOR_QUAD_CurrentVersionRun_f6b3 {
  strings:
    $key_f6b3 = { a5 dc [2] 81 d2 [2] aa fe [2] 84 dc [2] 90 c7 [2] 9f dd [2] 81 c0 [2] 83 c1 [2] 98 c7 [2] 84 c0 [2] 98 ef }

  condition:
    any of them
}