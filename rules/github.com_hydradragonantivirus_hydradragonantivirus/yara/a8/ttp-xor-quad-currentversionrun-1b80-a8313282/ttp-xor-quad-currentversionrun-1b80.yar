rule TTP_XOR_QUAD_CurrentVersionRun_1b80 {
  strings:
    $key_1b80 = { 48 ef [2] 6c e1 [2] 47 cd [2] 69 ef [2] 7d f4 [2] 72 ee [2] 6c f3 [2] 6e f2 [2] 75 f4 [2] 69 f3 [2] 75 dc }

  condition:
    any of them
}