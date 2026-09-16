rule TTP_XOR_QUAD_CurrentVersionRun_7b80 {
  strings:
    $key_7b80 = { 28 ef [2] 0c e1 [2] 27 cd [2] 09 ef [2] 1d f4 [2] 12 ee [2] 0c f3 [2] 0e f2 [2] 15 f4 [2] 09 f3 [2] 15 dc }

  condition:
    any of them
}