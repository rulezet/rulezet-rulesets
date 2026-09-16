rule TTP_XOR_QUAD_CurrentVersionRun_4d96 {
  strings:
    $key_4d96 = { 1e f9 [2] 3a f7 [2] 11 db [2] 3f f9 [2] 2b e2 [2] 24 f8 [2] 3a e5 [2] 38 e4 [2] 23 e2 [2] 3f e5 [2] 23 ca }

  condition:
    any of them
}