rule TTP_XOR_QUAD_CurrentVersionRun_7e96 {
  strings:
    $key_7e96 = { 2d f9 [2] 09 f7 [2] 22 db [2] 0c f9 [2] 18 e2 [2] 17 f8 [2] 09 e5 [2] 0b e4 [2] 10 e2 [2] 0c e5 [2] 10 ca }

  condition:
    any of them
}