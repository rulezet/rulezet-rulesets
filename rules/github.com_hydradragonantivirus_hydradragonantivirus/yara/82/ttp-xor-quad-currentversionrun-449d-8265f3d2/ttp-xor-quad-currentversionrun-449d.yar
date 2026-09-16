rule TTP_XOR_QUAD_CurrentVersionRun_449d {
  strings:
    $key_449d = { 17 f2 [2] 33 fc [2] 18 d0 [2] 36 f2 [2] 22 e9 [2] 2d f3 [2] 33 ee [2] 31 ef [2] 2a e9 [2] 36 ee [2] 2a c1 }

  condition:
    any of them
}