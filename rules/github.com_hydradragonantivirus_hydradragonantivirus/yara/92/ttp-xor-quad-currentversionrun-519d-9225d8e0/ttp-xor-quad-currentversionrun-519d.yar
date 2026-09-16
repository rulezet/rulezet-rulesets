rule TTP_XOR_QUAD_CurrentVersionRun_519d {
  strings:
    $key_519d = { 02 f2 [2] 26 fc [2] 0d d0 [2] 23 f2 [2] 37 e9 [2] 38 f3 [2] 26 ee [2] 24 ef [2] 3f e9 [2] 23 ee [2] 3f c1 }

  condition:
    any of them
}