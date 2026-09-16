rule TTP_XOR_QUAD_CurrentVersionRun_10ac {
  strings:
    $key_10ac = { 43 c3 [2] 67 cd [2] 4c e1 [2] 62 c3 [2] 76 d8 [2] 79 c2 [2] 67 df [2] 65 de [2] 7e d8 [2] 62 df [2] 7e f0 }

  condition:
    any of them
}