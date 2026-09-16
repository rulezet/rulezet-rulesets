rule TTP_XOR_QUAD_CurrentVersionRun_33b1 {
  strings:
    $key_33b1 = { 60 de [2] 44 d0 [2] 6f fc [2] 41 de [2] 55 c5 [2] 5a df [2] 44 c2 [2] 46 c3 [2] 5d c5 [2] 41 c2 [2] 5d ed }

  condition:
    any of them
}