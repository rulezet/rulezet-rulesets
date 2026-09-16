rule TTP_XOR_QUAD_CurrentVersionRun_539d {
  strings:
    $key_539d = { 00 f2 [2] 24 fc [2] 0f d0 [2] 21 f2 [2] 35 e9 [2] 3a f3 [2] 24 ee [2] 26 ef [2] 3d e9 [2] 21 ee [2] 3d c1 }

  condition:
    any of them
}