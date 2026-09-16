rule TTP_XOR_QUAD_CurrentVersionRun_0e96 {
  strings:
    $key_0e96 = { 5d f9 [2] 79 f7 [2] 52 db [2] 7c f9 [2] 68 e2 [2] 67 f8 [2] 79 e5 [2] 7b e4 [2] 60 e2 [2] 7c e5 [2] 60 ca }

  condition:
    any of them
}