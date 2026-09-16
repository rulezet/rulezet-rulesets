rule TTP_XOR_QUAD_CurrentVersionRun_389c {
  strings:
    $key_389c = { 6b f3 [2] 4f fd [2] 64 d1 [2] 4a f3 [2] 5e e8 [2] 51 f2 [2] 4f ef [2] 4d ee [2] 56 e8 [2] 4a ef [2] 56 c0 }

  condition:
    any of them
}