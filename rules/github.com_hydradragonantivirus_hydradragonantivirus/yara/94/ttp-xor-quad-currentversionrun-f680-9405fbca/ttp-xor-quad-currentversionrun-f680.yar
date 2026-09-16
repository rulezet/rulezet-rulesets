rule TTP_XOR_QUAD_CurrentVersionRun_f680 {
  strings:
    $key_f680 = { a5 ef [2] 81 e1 [2] aa cd [2] 84 ef [2] 90 f4 [2] 9f ee [2] 81 f3 [2] 83 f2 [2] 98 f4 [2] 84 f3 [2] 98 dc }

  condition:
    any of them
}