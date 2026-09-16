rule TTP_XOR_QUAD_CurrentVersionRun_0c9c {
  strings:
    $key_0c9c = { 5f f3 [2] 7b fd [2] 50 d1 [2] 7e f3 [2] 6a e8 [2] 65 f2 [2] 7b ef [2] 79 ee [2] 62 e8 [2] 7e ef [2] 62 c0 }

  condition:
    any of them
}