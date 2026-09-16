rule TTP_XOR_QUAD_CurrentVersionRun_6980 {
  strings:
    $key_6980 = { 3a ef [2] 1e e1 [2] 35 cd [2] 1b ef [2] 0f f4 [2] 00 ee [2] 1e f3 [2] 1c f2 [2] 07 f4 [2] 1b f3 [2] 07 dc }

  condition:
    any of them
}