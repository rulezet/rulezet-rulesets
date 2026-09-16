rule TTP_XOR_QUAD_CurrentVersionRun_4b96 {
  strings:
    $key_4b96 = { 18 f9 [2] 3c f7 [2] 17 db [2] 39 f9 [2] 2d e2 [2] 22 f8 [2] 3c e5 [2] 3e e4 [2] 25 e2 [2] 39 e5 [2] 25 ca }

  condition:
    any of them
}