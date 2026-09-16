rule TTP_XOR_QUAD_CurrentVersionRun_4f80 {
  strings:
    $key_4f80 = { 1c ef [2] 38 e1 [2] 13 cd [2] 3d ef [2] 29 f4 [2] 26 ee [2] 38 f3 [2] 3a f2 [2] 21 f4 [2] 3d f3 [2] 21 dc }

  condition:
    any of them
}