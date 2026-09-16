rule TTP_XOR_QUAD_CurrentVersionRun_48ac {
  strings:
    $key_48ac = { 1b c3 [2] 3f cd [2] 14 e1 [2] 3a c3 [2] 2e d8 [2] 21 c2 [2] 3f df [2] 3d de [2] 26 d8 [2] 3a df [2] 26 f0 }

  condition:
    any of them
}