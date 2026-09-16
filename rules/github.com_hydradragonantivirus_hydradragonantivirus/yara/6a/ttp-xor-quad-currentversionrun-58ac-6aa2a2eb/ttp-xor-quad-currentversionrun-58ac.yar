rule TTP_XOR_QUAD_CurrentVersionRun_58ac {
  strings:
    $key_58ac = { 0b c3 [2] 2f cd [2] 04 e1 [2] 2a c3 [2] 3e d8 [2] 31 c2 [2] 2f df [2] 2d de [2] 36 d8 [2] 2a df [2] 36 f0 }

  condition:
    any of them
}