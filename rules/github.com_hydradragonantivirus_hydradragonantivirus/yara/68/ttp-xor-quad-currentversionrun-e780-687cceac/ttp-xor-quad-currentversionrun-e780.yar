rule TTP_XOR_QUAD_CurrentVersionRun_e780 {
  strings:
    $key_e780 = { b4 ef [2] 90 e1 [2] bb cd [2] 95 ef [2] 81 f4 [2] 8e ee [2] 90 f3 [2] 92 f2 [2] 89 f4 [2] 95 f3 [2] 89 dc }

  condition:
    any of them
}