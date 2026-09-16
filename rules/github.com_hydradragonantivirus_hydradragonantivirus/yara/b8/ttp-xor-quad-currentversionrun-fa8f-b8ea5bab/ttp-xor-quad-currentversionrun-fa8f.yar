rule TTP_XOR_QUAD_CurrentVersionRun_fa8f {
  strings:
    $key_fa8f = { a9 e0 [2] 8d ee [2] a6 c2 [2] 88 e0 [2] 9c fb [2] 93 e1 [2] 8d fc [2] 8f fd [2] 94 fb [2] 88 fc [2] 94 d3 }

  condition:
    any of them
}