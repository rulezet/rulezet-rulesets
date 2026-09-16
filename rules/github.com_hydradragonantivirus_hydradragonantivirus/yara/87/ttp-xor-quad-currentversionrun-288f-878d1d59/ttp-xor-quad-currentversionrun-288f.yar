rule TTP_XOR_QUAD_CurrentVersionRun_288f {
  strings:
    $key_288f = { 7b e0 [2] 5f ee [2] 74 c2 [2] 5a e0 [2] 4e fb [2] 41 e1 [2] 5f fc [2] 5d fd [2] 46 fb [2] 5a fc [2] 46 d3 }

  condition:
    any of them
}