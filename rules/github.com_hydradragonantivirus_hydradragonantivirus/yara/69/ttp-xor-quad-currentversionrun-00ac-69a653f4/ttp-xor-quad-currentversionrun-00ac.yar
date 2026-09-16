rule TTP_XOR_QUAD_CurrentVersionRun_00ac {
  strings:
    $key_00ac = { 53 c3 [2] 77 cd [2] 5c e1 [2] 72 c3 [2] 66 d8 [2] 69 c2 [2] 77 df [2] 75 de [2] 6e d8 [2] 72 df [2] 6e f0 }

  condition:
    any of them
}