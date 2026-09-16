rule TTP_XOR_QUAD_CurrentVersionRun_5880 {
  strings:
    $key_5880 = { 0b ef [2] 2f e1 [2] 04 cd [2] 2a ef [2] 3e f4 [2] 31 ee [2] 2f f3 [2] 2d f2 [2] 36 f4 [2] 2a f3 [2] 36 dc }

  condition:
    any of them
}