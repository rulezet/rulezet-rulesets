rule TTP_XOR_QUAD_CurrentVersionRun_72ac {
  strings:
    $key_72ac = { 21 c3 [2] 05 cd [2] 2e e1 [2] 00 c3 [2] 14 d8 [2] 1b c2 [2] 05 df [2] 07 de [2] 1c d8 [2] 00 df [2] 1c f0 }

  condition:
    any of them
}