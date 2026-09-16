rule TTP_XOR_QUAD_CurrentVersionRun_5b80 {
  strings:
    $key_5b80 = { 08 ef [2] 2c e1 [2] 07 cd [2] 29 ef [2] 3d f4 [2] 32 ee [2] 2c f3 [2] 2e f2 [2] 35 f4 [2] 29 f3 [2] 35 dc }

  condition:
    any of them
}