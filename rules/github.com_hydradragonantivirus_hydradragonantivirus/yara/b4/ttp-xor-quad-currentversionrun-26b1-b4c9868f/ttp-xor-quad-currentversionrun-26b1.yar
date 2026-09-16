rule TTP_XOR_QUAD_CurrentVersionRun_26b1 {
  strings:
    $key_26b1 = { 75 de [2] 51 d0 [2] 7a fc [2] 54 de [2] 40 c5 [2] 4f df [2] 51 c2 [2] 53 c3 [2] 48 c5 [2] 54 c2 [2] 48 ed }

  condition:
    any of them
}