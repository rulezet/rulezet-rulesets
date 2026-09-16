rule TTP_XOR_QUAD_CurrentVersionRun_0b80 {
  strings:
    $key_0b80 = { 58 ef [2] 7c e1 [2] 57 cd [2] 79 ef [2] 6d f4 [2] 62 ee [2] 7c f3 [2] 7e f2 [2] 65 f4 [2] 79 f3 [2] 65 dc }

  condition:
    any of them
}