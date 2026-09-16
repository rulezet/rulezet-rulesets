rule TTP_XOR_QUAD_CurrentVersionRun_1f80 {
  strings:
    $key_1f80 = { 4c ef [2] 68 e1 [2] 43 cd [2] 6d ef [2] 79 f4 [2] 76 ee [2] 68 f3 [2] 6a f2 [2] 71 f4 [2] 6d f3 [2] 71 dc }

  condition:
    any of them
}