rule TTP_XOR_QUAD_CurrentVersionRun_1e80 {
  strings:
    $key_1e80 = { 4d ef [2] 69 e1 [2] 42 cd [2] 6c ef [2] 78 f4 [2] 77 ee [2] 69 f3 [2] 6b f2 [2] 70 f4 [2] 6c f3 [2] 70 dc }

  condition:
    any of them
}