rule TTP_XOR_QUAD_CurrentVersionRun_f49d {
  strings:
    $key_f49d = { a7 f2 [2] 83 fc [2] a8 d0 [2] 86 f2 [2] 92 e9 [2] 9d f3 [2] 83 ee [2] 81 ef [2] 9a e9 [2] 86 ee [2] 9a c1 }

  condition:
    any of them
}