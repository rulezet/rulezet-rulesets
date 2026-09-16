rule TTP_XOR_QUAD_CurrentVersionRun_039d {
  strings:
    $key_039d = { 50 f2 [2] 74 fc [2] 5f d0 [2] 71 f2 [2] 65 e9 [2] 6a f3 [2] 74 ee [2] 76 ef [2] 6d e9 [2] 71 ee [2] 6d c1 }

  condition:
    any of them
}