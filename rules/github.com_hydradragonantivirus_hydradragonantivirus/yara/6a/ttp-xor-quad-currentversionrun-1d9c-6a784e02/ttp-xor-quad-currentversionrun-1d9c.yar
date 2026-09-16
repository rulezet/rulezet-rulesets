rule TTP_XOR_QUAD_CurrentVersionRun_1d9c {
  strings:
    $key_1d9c = { 4e f3 [2] 6a fd [2] 41 d1 [2] 6f f3 [2] 7b e8 [2] 74 f2 [2] 6a ef [2] 68 ee [2] 73 e8 [2] 6f ef [2] 73 c0 }

  condition:
    any of them
}