rule TTP_XOR_QUAD_CurrentVersionRun_25ac {
  strings:
    $key_25ac = { 76 c3 [2] 52 cd [2] 79 e1 [2] 57 c3 [2] 43 d8 [2] 4c c2 [2] 52 df [2] 50 de [2] 4b d8 [2] 57 df [2] 4b f0 }

  condition:
    any of them
}