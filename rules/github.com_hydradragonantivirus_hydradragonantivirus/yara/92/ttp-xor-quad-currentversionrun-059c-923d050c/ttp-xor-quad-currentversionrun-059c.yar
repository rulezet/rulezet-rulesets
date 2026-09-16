rule TTP_XOR_QUAD_CurrentVersionRun_059c {
  strings:
    $key_059c = { 56 f3 [2] 72 fd [2] 59 d1 [2] 77 f3 [2] 63 e8 [2] 6c f2 [2] 72 ef [2] 70 ee [2] 6b e8 [2] 77 ef [2] 6b c0 }

  condition:
    any of them
}