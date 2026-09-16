rule TTP_XOR_QUAD_CurrentVersionRun_6d9d {
  strings:
    $key_6d9d = { 3e f2 [2] 1a fc [2] 31 d0 [2] 1f f2 [2] 0b e9 [2] 04 f3 [2] 1a ee [2] 18 ef [2] 03 e9 [2] 1f ee [2] 03 c1 }

  condition:
    any of them
}