rule TTP_XOR_QUAD_CurrentVersionRun_238f {
  strings:
    $key_238f = { 70 e0 [2] 54 ee [2] 7f c2 [2] 51 e0 [2] 45 fb [2] 4a e1 [2] 54 fc [2] 56 fd [2] 4d fb [2] 51 fc [2] 4d d3 }

  condition:
    any of them
}