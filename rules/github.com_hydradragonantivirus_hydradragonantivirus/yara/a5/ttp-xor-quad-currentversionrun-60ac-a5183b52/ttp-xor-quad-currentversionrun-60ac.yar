rule TTP_XOR_QUAD_CurrentVersionRun_60ac {
  strings:
    $key_60ac = { 33 c3 [2] 17 cd [2] 3c e1 [2] 12 c3 [2] 06 d8 [2] 09 c2 [2] 17 df [2] 15 de [2] 0e d8 [2] 12 df [2] 0e f0 }

  condition:
    any of them
}