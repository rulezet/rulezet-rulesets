rule TTP_XOR_QUAD_CurrentVersionRun_6f96 {
  strings:
    $key_6f96 = { 3c f9 [2] 18 f7 [2] 33 db [2] 1d f9 [2] 09 e2 [2] 06 f8 [2] 18 e5 [2] 1a e4 [2] 01 e2 [2] 1d e5 [2] 01 ca }

  condition:
    any of them
}