rule TTP_XOR_QUAD_CurrentVersionRun_319c {
  strings:
    $key_319c = { 62 f3 [2] 46 fd [2] 6d d1 [2] 43 f3 [2] 57 e8 [2] 58 f2 [2] 46 ef [2] 44 ee [2] 5f e8 [2] 43 ef [2] 5f c0 }

  condition:
    any of them
}