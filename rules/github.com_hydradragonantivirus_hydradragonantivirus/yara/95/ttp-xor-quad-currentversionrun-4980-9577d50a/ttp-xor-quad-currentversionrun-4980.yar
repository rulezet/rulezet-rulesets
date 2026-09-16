rule TTP_XOR_QUAD_CurrentVersionRun_4980 {
  strings:
    $key_4980 = { 1a ef [2] 3e e1 [2] 15 cd [2] 3b ef [2] 2f f4 [2] 20 ee [2] 3e f3 [2] 3c f2 [2] 27 f4 [2] 3b f3 [2] 27 dc }

  condition:
    any of them
}