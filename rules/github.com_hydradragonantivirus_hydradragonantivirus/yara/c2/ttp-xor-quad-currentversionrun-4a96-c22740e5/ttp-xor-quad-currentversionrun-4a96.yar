rule TTP_XOR_QUAD_CurrentVersionRun_4a96 {
  strings:
    $key_4a96 = { 19 f9 [2] 3d f7 [2] 16 db [2] 38 f9 [2] 2c e2 [2] 23 f8 [2] 3d e5 [2] 3f e4 [2] 24 e2 [2] 38 e5 [2] 24 ca }

  condition:
    any of them
}