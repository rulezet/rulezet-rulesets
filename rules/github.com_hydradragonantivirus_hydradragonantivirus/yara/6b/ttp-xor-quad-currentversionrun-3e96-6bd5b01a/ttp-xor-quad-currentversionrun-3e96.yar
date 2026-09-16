rule TTP_XOR_QUAD_CurrentVersionRun_3e96 {
  strings:
    $key_3e96 = { 6d f9 [2] 49 f7 [2] 62 db [2] 4c f9 [2] 58 e2 [2] 57 f8 [2] 49 e5 [2] 4b e4 [2] 50 e2 [2] 4c e5 [2] 50 ca }

  condition:
    any of them
}