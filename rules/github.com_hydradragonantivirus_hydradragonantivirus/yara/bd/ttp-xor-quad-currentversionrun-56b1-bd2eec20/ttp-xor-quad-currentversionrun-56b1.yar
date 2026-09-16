rule TTP_XOR_QUAD_CurrentVersionRun_56b1 {
  strings:
    $key_56b1 = { 05 de [2] 21 d0 [2] 0a fc [2] 24 de [2] 30 c5 [2] 3f df [2] 21 c2 [2] 23 c3 [2] 38 c5 [2] 24 c2 [2] 38 ed }

  condition:
    any of them
}