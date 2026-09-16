rule TTP_XOR_QUAD_CurrentVersionRun_5f96 {
  strings:
    $key_5f96 = { 0c f9 [2] 28 f7 [2] 03 db [2] 2d f9 [2] 39 e2 [2] 36 f8 [2] 28 e5 [2] 2a e4 [2] 31 e2 [2] 2d e5 [2] 31 ca }

  condition:
    any of them
}