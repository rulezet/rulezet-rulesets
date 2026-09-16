rule TTP_XOR_QUAD_CurrentVersionRun_c4ac {
  strings:
    $key_c4ac = { 97 c3 [2] b3 cd [2] 98 e1 [2] b6 c3 [2] a2 d8 [2] ad c2 [2] b3 df [2] b1 de [2] aa d8 [2] b6 df [2] aa f0 }

  condition:
    any of them
}