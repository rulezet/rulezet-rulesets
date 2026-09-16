rule TTP_XOR_QUAD_CurrentVersionRun_549d {
  strings:
    $key_549d = { 07 f2 [2] 23 fc [2] 08 d0 [2] 26 f2 [2] 32 e9 [2] 3d f3 [2] 23 ee [2] 21 ef [2] 3a e9 [2] 26 ee [2] 3a c1 }

  condition:
    any of them
}