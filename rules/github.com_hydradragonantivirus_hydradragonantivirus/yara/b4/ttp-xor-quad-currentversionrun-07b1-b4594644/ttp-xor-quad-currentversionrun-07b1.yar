rule TTP_XOR_QUAD_CurrentVersionRun_07b1 {
  strings:
    $key_07b1 = { 54 de [2] 70 d0 [2] 5b fc [2] 75 de [2] 61 c5 [2] 6e df [2] 70 c2 [2] 72 c3 [2] 69 c5 [2] 75 c2 [2] 69 ed }

  condition:
    any of them
}