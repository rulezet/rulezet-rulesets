rule TTP_XOR_QUAD_CurrentVersionRun_32ac {
  strings:
    $key_32ac = { 61 c3 [2] 45 cd [2] 6e e1 [2] 40 c3 [2] 54 d8 [2] 5b c2 [2] 45 df [2] 47 de [2] 5c d8 [2] 40 df [2] 5c f0 }

  condition:
    any of them
}