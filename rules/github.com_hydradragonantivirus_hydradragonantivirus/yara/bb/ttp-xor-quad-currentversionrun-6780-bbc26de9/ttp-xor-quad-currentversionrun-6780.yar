rule TTP_XOR_QUAD_CurrentVersionRun_6780 {
  strings:
    $key_6780 = { 34 ef [2] 10 e1 [2] 3b cd [2] 15 ef [2] 01 f4 [2] 0e ee [2] 10 f3 [2] 12 f2 [2] 09 f4 [2] 15 f3 [2] 09 dc }

  condition:
    any of them
}