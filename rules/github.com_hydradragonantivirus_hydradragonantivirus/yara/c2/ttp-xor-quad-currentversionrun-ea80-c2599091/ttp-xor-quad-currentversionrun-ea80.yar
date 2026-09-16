rule TTP_XOR_QUAD_CurrentVersionRun_ea80 {
  strings:
    $key_ea80 = { b9 ef [2] 9d e1 [2] b6 cd [2] 98 ef [2] 8c f4 [2] 83 ee [2] 9d f3 [2] 9f f2 [2] 84 f4 [2] 98 f3 [2] 84 dc }

  condition:
    any of them
}