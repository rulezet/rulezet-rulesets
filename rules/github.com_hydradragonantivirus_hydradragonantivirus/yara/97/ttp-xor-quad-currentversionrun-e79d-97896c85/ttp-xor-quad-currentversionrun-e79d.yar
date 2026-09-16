rule TTP_XOR_QUAD_CurrentVersionRun_e79d {
  strings:
    $key_e79d = { b4 f2 [2] 90 fc [2] bb d0 [2] 95 f2 [2] 81 e9 [2] 8e f3 [2] 90 ee [2] 92 ef [2] 89 e9 [2] 95 ee [2] 89 c1 }

  condition:
    any of them
}