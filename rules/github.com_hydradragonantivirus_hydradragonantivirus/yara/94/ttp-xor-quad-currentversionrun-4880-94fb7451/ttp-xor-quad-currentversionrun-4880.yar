rule TTP_XOR_QUAD_CurrentVersionRun_4880 {
  strings:
    $key_4880 = { 1b ef [2] 3f e1 [2] 14 cd [2] 3a ef [2] 2e f4 [2] 21 ee [2] 3f f3 [2] 3d f2 [2] 26 f4 [2] 3a f3 [2] 26 dc }

  condition:
    any of them
}