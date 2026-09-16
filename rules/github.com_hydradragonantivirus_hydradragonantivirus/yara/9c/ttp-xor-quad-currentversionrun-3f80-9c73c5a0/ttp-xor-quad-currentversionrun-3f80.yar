rule TTP_XOR_QUAD_CurrentVersionRun_3f80 {
  strings:
    $key_3f80 = { 6c ef [2] 48 e1 [2] 63 cd [2] 4d ef [2] 59 f4 [2] 56 ee [2] 48 f3 [2] 4a f2 [2] 51 f4 [2] 4d f3 [2] 51 dc }

  condition:
    any of them
}