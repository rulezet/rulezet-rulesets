rule TTP_XOR_QUAD_CurrentVersionRun_7a80 {
  strings:
    $key_7a80 = { 29 ef [2] 0d e1 [2] 26 cd [2] 08 ef [2] 1c f4 [2] 13 ee [2] 0d f3 [2] 0f f2 [2] 14 f4 [2] 08 f3 [2] 14 dc }

  condition:
    any of them
}