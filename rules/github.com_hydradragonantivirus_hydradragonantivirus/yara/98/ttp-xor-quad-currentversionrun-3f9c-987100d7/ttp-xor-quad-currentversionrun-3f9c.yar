rule TTP_XOR_QUAD_CurrentVersionRun_3f9c {
  strings:
    $key_3f9c = { 6c f3 [2] 48 fd [2] 63 d1 [2] 4d f3 [2] 59 e8 [2] 56 f2 [2] 48 ef [2] 4a ee [2] 51 e8 [2] 4d ef [2] 51 c0 }

  condition:
    any of them
}