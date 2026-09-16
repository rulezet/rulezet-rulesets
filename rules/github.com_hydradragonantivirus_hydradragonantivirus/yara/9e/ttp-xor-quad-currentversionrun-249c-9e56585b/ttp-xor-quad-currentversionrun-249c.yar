rule TTP_XOR_QUAD_CurrentVersionRun_249c {
  strings:
    $key_249c = { 77 f3 [2] 53 fd [2] 78 d1 [2] 56 f3 [2] 42 e8 [2] 4d f2 [2] 53 ef [2] 51 ee [2] 4a e8 [2] 56 ef [2] 4a c0 }

  condition:
    any of them
}