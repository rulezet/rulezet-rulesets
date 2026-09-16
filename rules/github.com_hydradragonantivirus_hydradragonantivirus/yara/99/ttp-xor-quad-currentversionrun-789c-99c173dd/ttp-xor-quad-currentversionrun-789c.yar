rule TTP_XOR_QUAD_CurrentVersionRun_789c {
  strings:
    $key_789c = { 2b f3 [2] 0f fd [2] 24 d1 [2] 0a f3 [2] 1e e8 [2] 11 f2 [2] 0f ef [2] 0d ee [2] 16 e8 [2] 0a ef [2] 16 c0 }

  condition:
    any of them
}