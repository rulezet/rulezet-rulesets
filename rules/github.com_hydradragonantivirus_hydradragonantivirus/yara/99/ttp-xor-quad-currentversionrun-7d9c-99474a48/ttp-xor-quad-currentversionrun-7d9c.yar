rule TTP_XOR_QUAD_CurrentVersionRun_7d9c {
  strings:
    $key_7d9c = { 2e f3 [2] 0a fd [2] 21 d1 [2] 0f f3 [2] 1b e8 [2] 14 f2 [2] 0a ef [2] 08 ee [2] 13 e8 [2] 0f ef [2] 13 c0 }

  condition:
    any of them
}