rule TTP_XOR_QUAD_CurrentVersionRun_4d80 {
  strings:
    $key_4d80 = { 1e ef [2] 3a e1 [2] 11 cd [2] 3f ef [2] 2b f4 [2] 24 ee [2] 3a f3 [2] 38 f2 [2] 23 f4 [2] 3f f3 [2] 23 dc }

  condition:
    any of them
}