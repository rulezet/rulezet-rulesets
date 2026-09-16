rule TTP_XOR_QUAD_CurrentVersionRun_53b1 {
  strings:
    $key_53b1 = { 00 de [2] 24 d0 [2] 0f fc [2] 21 de [2] 35 c5 [2] 3a df [2] 24 c2 [2] 26 c3 [2] 3d c5 [2] 21 c2 [2] 3d ed }

  condition:
    any of them
}