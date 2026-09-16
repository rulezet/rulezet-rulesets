rule TTP_XOR_QUAD_CurrentVersionRun_c88f {
  strings:
    $key_c88f = { 9b e0 [2] bf ee [2] 94 c2 [2] ba e0 [2] ae fb [2] a1 e1 [2] bf fc [2] bd fd [2] a6 fb [2] ba fc [2] a6 d3 }

  condition:
    any of them
}