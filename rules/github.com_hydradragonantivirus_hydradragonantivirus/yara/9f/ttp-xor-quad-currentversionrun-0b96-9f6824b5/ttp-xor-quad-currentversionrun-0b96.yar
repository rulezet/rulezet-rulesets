rule TTP_XOR_QUAD_CurrentVersionRun_0b96 {
  strings:
    $key_0b96 = { 58 f9 [2] 7c f7 [2] 57 db [2] 79 f9 [2] 6d e2 [2] 62 f8 [2] 7c e5 [2] 7e e4 [2] 65 e2 [2] 79 e5 [2] 65 ca }

  condition:
    any of them
}