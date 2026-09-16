rule TTP_XOR_QUAD_CurrentVersionRun_63b1 {
  strings:
    $key_63b1 = { 30 de [2] 14 d0 [2] 3f fc [2] 11 de [2] 05 c5 [2] 0a df [2] 14 c2 [2] 16 c3 [2] 0d c5 [2] 11 c2 [2] 0d ed }

  condition:
    any of them
}