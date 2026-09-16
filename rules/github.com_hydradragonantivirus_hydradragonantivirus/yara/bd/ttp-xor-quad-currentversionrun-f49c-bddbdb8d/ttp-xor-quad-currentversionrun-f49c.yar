rule TTP_XOR_QUAD_CurrentVersionRun_f49c {
  strings:
    $key_f49c = { a7 f3 [2] 83 fd [2] a8 d1 [2] 86 f3 [2] 92 e8 [2] 9d f2 [2] 83 ef [2] 81 ee [2] 9a e8 [2] 86 ef [2] 9a c0 }

  condition:
    any of them
}