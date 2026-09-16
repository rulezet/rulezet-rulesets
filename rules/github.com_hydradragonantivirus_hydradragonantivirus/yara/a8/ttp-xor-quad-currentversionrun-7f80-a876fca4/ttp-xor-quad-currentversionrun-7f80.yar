rule TTP_XOR_QUAD_CurrentVersionRun_7f80 {
  strings:
    $key_7f80 = { 2c ef [2] 08 e1 [2] 23 cd [2] 0d ef [2] 19 f4 [2] 16 ee [2] 08 f3 [2] 0a f2 [2] 11 f4 [2] 0d f3 [2] 11 dc }

  condition:
    any of them
}