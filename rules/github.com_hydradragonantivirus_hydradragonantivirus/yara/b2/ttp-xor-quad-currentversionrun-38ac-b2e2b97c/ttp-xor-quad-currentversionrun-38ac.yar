rule TTP_XOR_QUAD_CurrentVersionRun_38ac {
  strings:
    $key_38ac = { 6b c3 [2] 4f cd [2] 64 e1 [2] 4a c3 [2] 5e d8 [2] 51 c2 [2] 4f df [2] 4d de [2] 56 d8 [2] 4a df [2] 56 f0 }

  condition:
    any of them
}