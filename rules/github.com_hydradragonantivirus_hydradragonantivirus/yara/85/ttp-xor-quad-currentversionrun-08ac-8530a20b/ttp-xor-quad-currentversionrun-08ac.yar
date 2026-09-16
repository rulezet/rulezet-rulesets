rule TTP_XOR_QUAD_CurrentVersionRun_08ac {
  strings:
    $key_08ac = { 5b c3 [2] 7f cd [2] 54 e1 [2] 7a c3 [2] 6e d8 [2] 61 c2 [2] 7f df [2] 7d de [2] 66 d8 [2] 7a df [2] 66 f0 }

  condition:
    any of them
}