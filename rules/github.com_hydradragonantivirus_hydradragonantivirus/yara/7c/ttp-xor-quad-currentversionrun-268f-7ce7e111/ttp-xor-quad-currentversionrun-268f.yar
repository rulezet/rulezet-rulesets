rule TTP_XOR_QUAD_CurrentVersionRun_268f {
  strings:
    $key_268f = { 75 e0 [2] 51 ee [2] 7a c2 [2] 54 e0 [2] 40 fb [2] 4f e1 [2] 51 fc [2] 53 fd [2] 48 fb [2] 54 fc [2] 48 d3 }

  condition:
    any of them
}