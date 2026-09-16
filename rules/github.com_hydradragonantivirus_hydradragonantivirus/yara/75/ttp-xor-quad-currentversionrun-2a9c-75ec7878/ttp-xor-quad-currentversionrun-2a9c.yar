rule TTP_XOR_QUAD_CurrentVersionRun_2a9c {
  strings:
    $key_2a9c = { 79 f3 [2] 5d fd [2] 76 d1 [2] 58 f3 [2] 4c e8 [2] 43 f2 [2] 5d ef [2] 5f ee [2] 44 e8 [2] 58 ef [2] 44 c0 }

  condition:
    any of them
}