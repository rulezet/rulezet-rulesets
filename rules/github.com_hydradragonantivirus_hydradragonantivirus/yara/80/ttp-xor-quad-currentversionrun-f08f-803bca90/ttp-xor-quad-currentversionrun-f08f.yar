rule TTP_XOR_QUAD_CurrentVersionRun_f08f {
  strings:
    $key_f08f = { a3 e0 [2] 87 ee [2] ac c2 [2] 82 e0 [2] 96 fb [2] 99 e1 [2] 87 fc [2] 85 fd [2] 9e fb [2] 82 fc [2] 9e d3 }

  condition:
    any of them
}