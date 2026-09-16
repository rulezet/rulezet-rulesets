rule TTP_XOR_QUAD_CurrentVersionRun_3d9c {
  strings:
    $key_3d9c = { 6e f3 [2] 4a fd [2] 61 d1 [2] 4f f3 [2] 5b e8 [2] 54 f2 [2] 4a ef [2] 48 ee [2] 53 e8 [2] 4f ef [2] 53 c0 }

  condition:
    any of them
}