rule TTP_XOR_QUAD_CurrentVersionRun_1d80 {
  strings:
    $key_1d80 = { 4e ef [2] 6a e1 [2] 41 cd [2] 6f ef [2] 7b f4 [2] 74 ee [2] 6a f3 [2] 68 f2 [2] 73 f4 [2] 6f f3 [2] 73 dc }

  condition:
    any of them
}