rule TTP_XOR_QUAD_CurrentVersionRun_109c {
  strings:
    $key_109c = { 43 f3 [2] 67 fd [2] 4c d1 [2] 62 f3 [2] 76 e8 [2] 79 f2 [2] 67 ef [2] 65 ee [2] 7e e8 [2] 62 ef [2] 7e c0 }

  condition:
    any of them
}