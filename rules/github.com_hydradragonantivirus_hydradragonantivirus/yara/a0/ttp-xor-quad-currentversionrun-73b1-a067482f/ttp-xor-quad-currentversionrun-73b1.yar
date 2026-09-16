rule TTP_XOR_QUAD_CurrentVersionRun_73b1 {
  strings:
    $key_73b1 = { 20 de [2] 04 d0 [2] 2f fc [2] 01 de [2] 15 c5 [2] 1a df [2] 04 c2 [2] 06 c3 [2] 1d c5 [2] 01 c2 [2] 1d ed }

  condition:
    any of them
}