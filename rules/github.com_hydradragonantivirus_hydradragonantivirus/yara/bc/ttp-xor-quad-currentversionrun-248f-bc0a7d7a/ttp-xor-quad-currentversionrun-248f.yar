rule TTP_XOR_QUAD_CurrentVersionRun_248f {
  strings:
    $key_248f = { 77 e0 [2] 53 ee [2] 78 c2 [2] 56 e0 [2] 42 fb [2] 4d e1 [2] 53 fc [2] 51 fd [2] 4a fb [2] 56 fc [2] 4a d3 }

  condition:
    any of them
}