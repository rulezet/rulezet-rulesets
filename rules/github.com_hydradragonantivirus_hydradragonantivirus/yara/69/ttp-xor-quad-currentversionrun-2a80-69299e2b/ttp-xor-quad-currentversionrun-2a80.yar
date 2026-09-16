rule TTP_XOR_QUAD_CurrentVersionRun_2a80 {
  strings:
    $key_2a80 = { 79 ef [2] 5d e1 [2] 76 cd [2] 58 ef [2] 4c f4 [2] 43 ee [2] 5d f3 [2] 5f f2 [2] 44 f4 [2] 58 f3 [2] 44 dc }

  condition:
    any of them
}