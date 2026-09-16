rule TTP_XOR_QUAD_CurrentVersionRun_788f {
  strings:
    $key_788f = { 2b e0 [2] 0f ee [2] 24 c2 [2] 0a e0 [2] 1e fb [2] 11 e1 [2] 0f fc [2] 0d fd [2] 16 fb [2] 0a fc [2] 16 d3 }

  condition:
    any of them
}