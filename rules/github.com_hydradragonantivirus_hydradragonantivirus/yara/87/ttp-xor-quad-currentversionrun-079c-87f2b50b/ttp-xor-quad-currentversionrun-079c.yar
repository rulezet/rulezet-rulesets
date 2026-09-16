rule TTP_XOR_QUAD_CurrentVersionRun_079c {
  strings:
    $key_079c = { 54 f3 [2] 70 fd [2] 5b d1 [2] 75 f3 [2] 61 e8 [2] 6e f2 [2] 70 ef [2] 72 ee [2] 69 e8 [2] 75 ef [2] 69 c0 }

  condition:
    any of them
}