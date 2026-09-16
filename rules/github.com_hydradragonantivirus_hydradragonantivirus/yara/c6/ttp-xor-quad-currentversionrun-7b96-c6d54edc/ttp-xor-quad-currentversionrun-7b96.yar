rule TTP_XOR_QUAD_CurrentVersionRun_7b96 {
  strings:
    $key_7b96 = { 28 f9 [2] 0c f7 [2] 27 db [2] 09 f9 [2] 1d e2 [2] 12 f8 [2] 0c e5 [2] 0e e4 [2] 15 e2 [2] 09 e5 [2] 15 ca }

  condition:
    any of them
}