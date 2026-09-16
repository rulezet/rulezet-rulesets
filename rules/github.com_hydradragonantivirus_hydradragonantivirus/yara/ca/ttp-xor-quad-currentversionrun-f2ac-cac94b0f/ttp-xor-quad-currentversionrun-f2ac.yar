rule TTP_XOR_QUAD_CurrentVersionRun_f2ac {
  strings:
    $key_f2ac = { a1 c3 [2] 85 cd [2] ae e1 [2] 80 c3 [2] 94 d8 [2] 9b c2 [2] 85 df [2] 87 de [2] 9c d8 [2] 80 df [2] 9c f0 }

  condition:
    any of them
}