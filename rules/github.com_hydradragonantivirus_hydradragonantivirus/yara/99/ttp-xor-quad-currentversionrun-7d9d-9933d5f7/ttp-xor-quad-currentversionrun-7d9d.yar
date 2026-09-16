rule TTP_XOR_QUAD_CurrentVersionRun_7d9d {
  strings:
    $key_7d9d = { 2e f2 [2] 0a fc [2] 21 d0 [2] 0f f2 [2] 1b e9 [2] 14 f3 [2] 0a ee [2] 08 ef [2] 13 e9 [2] 0f ee [2] 13 c1 }

  condition:
    any of them
}