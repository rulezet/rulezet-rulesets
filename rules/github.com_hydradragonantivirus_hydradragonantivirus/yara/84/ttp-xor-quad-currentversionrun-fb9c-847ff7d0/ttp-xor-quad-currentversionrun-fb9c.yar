rule TTP_XOR_QUAD_CurrentVersionRun_fb9c {
  strings:
    $key_fb9c = { a8 f3 [2] 8c fd [2] a7 d1 [2] 89 f3 [2] 9d e8 [2] 92 f2 [2] 8c ef [2] 8e ee [2] 95 e8 [2] 89 ef [2] 95 c0 }

  condition:
    any of them
}