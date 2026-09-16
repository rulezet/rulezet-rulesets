rule TTP_XOR_QUAD_CurrentVersionRun_549c {
  strings:
    $key_549c = { 07 f3 [2] 23 fd [2] 08 d1 [2] 26 f3 [2] 32 e8 [2] 3d f2 [2] 23 ef [2] 21 ee [2] 3a e8 [2] 26 ef [2] 3a c0 }

  condition:
    any of them
}