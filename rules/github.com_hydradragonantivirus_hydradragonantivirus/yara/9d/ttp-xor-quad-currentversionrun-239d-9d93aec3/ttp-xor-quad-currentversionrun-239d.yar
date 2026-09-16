rule TTP_XOR_QUAD_CurrentVersionRun_239d {
  strings:
    $key_239d = { 70 f2 [2] 54 fc [2] 7f d0 [2] 51 f2 [2] 45 e9 [2] 4a f3 [2] 54 ee [2] 56 ef [2] 4d e9 [2] 51 ee [2] 4d c1 }

  condition:
    any of them
}