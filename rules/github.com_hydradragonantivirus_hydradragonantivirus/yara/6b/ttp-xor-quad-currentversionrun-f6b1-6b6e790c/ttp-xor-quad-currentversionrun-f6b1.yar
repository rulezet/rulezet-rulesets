rule TTP_XOR_QUAD_CurrentVersionRun_f6b1 {
  strings:
    $key_f6b1 = { a5 de [2] 81 d0 [2] aa fc [2] 84 de [2] 90 c5 [2] 9f df [2] 81 c2 [2] 83 c3 [2] 98 c5 [2] 84 c2 [2] 98 ed }

  condition:
    any of them
}