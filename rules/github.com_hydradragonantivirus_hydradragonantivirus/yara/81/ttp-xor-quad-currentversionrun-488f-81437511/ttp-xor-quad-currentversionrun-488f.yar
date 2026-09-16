rule TTP_XOR_QUAD_CurrentVersionRun_488f {
  strings:
    $key_488f = { 1b e0 [2] 3f ee [2] 14 c2 [2] 3a e0 [2] 2e fb [2] 21 e1 [2] 3f fc [2] 3d fd [2] 26 fb [2] 3a fc [2] 26 d3 }

  condition:
    any of them
}