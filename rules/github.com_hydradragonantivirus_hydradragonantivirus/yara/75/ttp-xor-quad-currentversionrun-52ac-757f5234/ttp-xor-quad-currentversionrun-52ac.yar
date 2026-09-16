rule TTP_XOR_QUAD_CurrentVersionRun_52ac {
  strings:
    $key_52ac = { 01 c3 [2] 25 cd [2] 0e e1 [2] 20 c3 [2] 34 d8 [2] 3b c2 [2] 25 df [2] 27 de [2] 3c d8 [2] 20 df [2] 3c f0 }

  condition:
    any of them
}