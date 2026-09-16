rule TTP_XOR_QUAD_CurrentVersionRun_188f {
  strings:
    $key_188f = { 4b e0 [2] 6f ee [2] 44 c2 [2] 6a e0 [2] 7e fb [2] 71 e1 [2] 6f fc [2] 6d fd [2] 76 fb [2] 6a fc [2] 76 d3 }

  condition:
    any of them
}