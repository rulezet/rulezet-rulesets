rule TTP_XOR_QUAD_CurrentVersionRun_5d80 {
  strings:
    $key_5d80 = { 0e ef [2] 2a e1 [2] 01 cd [2] 2f ef [2] 3b f4 [2] 34 ee [2] 2a f3 [2] 28 f2 [2] 33 f4 [2] 2f f3 [2] 33 dc }

  condition:
    any of them
}