rule TTP_XOR_QUAD_CurrentVersionRun_f49b {
  strings:
    $key_f49b = { a7 f4 [2] 83 fa [2] a8 d6 [2] 86 f4 [2] 92 ef [2] 9d f5 [2] 83 e8 [2] 81 e9 [2] 9a ef [2] 86 e8 [2] 9a c7 }

  condition:
    any of them
}