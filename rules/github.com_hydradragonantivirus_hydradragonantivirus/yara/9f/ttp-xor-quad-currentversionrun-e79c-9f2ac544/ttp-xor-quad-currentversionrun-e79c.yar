rule TTP_XOR_QUAD_CurrentVersionRun_e79c {
  strings:
    $key_e79c = { b4 f3 [2] 90 fd [2] bb d1 [2] 95 f3 [2] 81 e8 [2] 8e f2 [2] 90 ef [2] 92 ee [2] 89 e8 [2] 95 ef [2] 89 c0 }

  condition:
    any of them
}