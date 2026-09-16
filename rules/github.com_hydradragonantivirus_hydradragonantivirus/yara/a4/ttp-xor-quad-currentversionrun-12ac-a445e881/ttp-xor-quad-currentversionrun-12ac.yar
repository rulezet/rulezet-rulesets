rule TTP_XOR_QUAD_CurrentVersionRun_12ac {
  strings:
    $key_12ac = { 41 c3 [2] 65 cd [2] 4e e1 [2] 60 c3 [2] 74 d8 [2] 7b c2 [2] 65 df [2] 67 de [2] 7c d8 [2] 60 df [2] 7c f0 }

  condition:
    any of them
}