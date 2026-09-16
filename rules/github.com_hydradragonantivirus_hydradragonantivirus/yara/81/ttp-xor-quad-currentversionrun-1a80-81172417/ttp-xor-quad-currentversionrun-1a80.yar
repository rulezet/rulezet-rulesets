rule TTP_XOR_QUAD_CurrentVersionRun_1a80 {
  strings:
    $key_1a80 = { 49 ef [2] 6d e1 [2] 46 cd [2] 68 ef [2] 7c f4 [2] 73 ee [2] 6d f3 [2] 6f f2 [2] 74 f4 [2] 68 f3 [2] 74 dc }

  condition:
    any of them
}