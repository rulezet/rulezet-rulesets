rule TTP_XOR_QUAD_CurrentVersionRun_f0ac {
  strings:
    $key_f0ac = { a3 c3 [2] 87 cd [2] ac e1 [2] 82 c3 [2] 96 d8 [2] 99 c2 [2] 87 df [2] 85 de [2] 9e d8 [2] 82 df [2] 9e f0 }

  condition:
    any of them
}