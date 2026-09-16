rule TTP_XOR_QUAD_CurrentVersionRun_639d {
  strings:
    $key_639d = { 30 f2 [2] 14 fc [2] 3f d0 [2] 11 f2 [2] 05 e9 [2] 0a f3 [2] 14 ee [2] 16 ef [2] 0d e9 [2] 11 ee [2] 0d c1 }

  condition:
    any of them
}