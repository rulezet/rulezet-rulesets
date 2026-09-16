rule TTP_XOR_QUAD_CurrentVersionRun_5dac {
  strings:
    $key_5dac = { 0e c3 [2] 2a cd [2] 01 e1 [2] 2f c3 [2] 3b d8 [2] 34 c2 [2] 2a df [2] 28 de [2] 33 d8 [2] 2f df [2] 33 f0 }

  condition:
    any of them
}