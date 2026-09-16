rule TTP_XOR_QUAD_CurrentVersionRun_f58f {
  strings:
    $key_f58f = { a6 e0 [2] 82 ee [2] a9 c2 [2] 87 e0 [2] 93 fb [2] 9c e1 [2] 82 fc [2] 80 fd [2] 9b fb [2] 87 fc [2] 9b d3 }

  condition:
    any of them
}