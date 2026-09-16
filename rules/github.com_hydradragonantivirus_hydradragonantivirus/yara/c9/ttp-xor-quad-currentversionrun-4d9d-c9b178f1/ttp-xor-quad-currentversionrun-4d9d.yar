rule TTP_XOR_QUAD_CurrentVersionRun_4d9d {
  strings:
    $key_4d9d = { 1e f2 [2] 3a fc [2] 11 d0 [2] 3f f2 [2] 2b e9 [2] 24 f3 [2] 3a ee [2] 38 ef [2] 23 e9 [2] 3f ee [2] 23 c1 }

  condition:
    any of them
}