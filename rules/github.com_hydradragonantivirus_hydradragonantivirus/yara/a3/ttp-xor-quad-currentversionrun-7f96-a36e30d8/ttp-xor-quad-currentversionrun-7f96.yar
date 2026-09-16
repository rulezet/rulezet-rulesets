rule TTP_XOR_QUAD_CurrentVersionRun_7f96 {
  strings:
    $key_7f96 = { 2c f9 [2] 08 f7 [2] 23 db [2] 0d f9 [2] 19 e2 [2] 16 f8 [2] 08 e5 [2] 0a e4 [2] 11 e2 [2] 0d e5 [2] 11 ca }

  condition:
    any of them
}