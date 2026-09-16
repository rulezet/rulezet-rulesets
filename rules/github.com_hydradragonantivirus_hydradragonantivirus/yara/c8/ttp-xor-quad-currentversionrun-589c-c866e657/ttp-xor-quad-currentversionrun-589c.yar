rule TTP_XOR_QUAD_CurrentVersionRun_589c {
  strings:
    $key_589c = { 0b f3 [2] 2f fd [2] 04 d1 [2] 2a f3 [2] 3e e8 [2] 31 f2 [2] 2f ef [2] 2d ee [2] 36 e8 [2] 2a ef [2] 36 c0 }

  condition:
    any of them
}