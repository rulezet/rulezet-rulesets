rule TTP_XOR_QUAD_CurrentVersionRun_259c {
  strings:
    $key_259c = { 76 f3 [2] 52 fd [2] 79 d1 [2] 57 f3 [2] 43 e8 [2] 4c f2 [2] 52 ef [2] 50 ee [2] 4b e8 [2] 57 ef [2] 4b c0 }

  condition:
    any of them
}