rule TTP_XOR_QUAD_CurrentVersionRun_40ac {
  strings:
    $key_40ac = { 13 c3 [2] 37 cd [2] 1c e1 [2] 32 c3 [2] 26 d8 [2] 29 c2 [2] 37 df [2] 35 de [2] 2e d8 [2] 32 df [2] 2e f0 }

  condition:
    any of them
}