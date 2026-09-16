rule TTP_XOR_QUAD_CurrentVersionRun_26ac {
  strings:
    $key_26ac = { 75 c3 [2] 51 cd [2] 7a e1 [2] 54 c3 [2] 40 d8 [2] 4f c2 [2] 51 df [2] 53 de [2] 48 d8 [2] 54 df [2] 48 f0 }

  condition:
    any of them
}