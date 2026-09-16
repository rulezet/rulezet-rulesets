rule TTP_XOR_QUAD_CurrentVersionRun_0f80 {
  strings:
    $key_0f80 = { 5c ef [2] 78 e1 [2] 53 cd [2] 7d ef [2] 69 f4 [2] 66 ee [2] 78 f3 [2] 7a f2 [2] 61 f4 [2] 7d f3 [2] 61 dc }

  condition:
    any of them
}