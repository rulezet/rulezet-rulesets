rule TTP_XOR_QUAD_CurrentVersionRun_36b1 {
  strings:
    $key_36b1 = { 65 de [2] 41 d0 [2] 6a fc [2] 44 de [2] 50 c5 [2] 5f df [2] 41 c2 [2] 43 c3 [2] 58 c5 [2] 44 c2 [2] 58 ed }

  condition:
    any of them
}