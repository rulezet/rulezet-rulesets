rule TTP_XOR_QUAD_CurrentVersionRun_e3b1 {
  strings:
    $key_e3b1 = { b0 de [2] 94 d0 [2] bf fc [2] 91 de [2] 85 c5 [2] 8a df [2] 94 c2 [2] 96 c3 [2] 8d c5 [2] 91 c2 [2] 8d ed }

  condition:
    any of them
}