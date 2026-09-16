rule TTP_XOR_QUAD_CurrentVersionRun_6c9c {
  strings:
    $key_6c9c = { 3f f3 [2] 1b fd [2] 30 d1 [2] 1e f3 [2] 0a e8 [2] 05 f2 [2] 1b ef [2] 19 ee [2] 02 e8 [2] 1e ef [2] 02 c0 }

  condition:
    any of them
}