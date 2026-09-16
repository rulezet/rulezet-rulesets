rule TTP_XOR_QUAD_CurrentVersionRun_54ac {
  strings:
    $key_54ac = { 07 c3 [2] 23 cd [2] 08 e1 [2] 26 c3 [2] 32 d8 [2] 3d c2 [2] 23 df [2] 21 de [2] 3a d8 [2] 26 df [2] 3a f0 }

  condition:
    any of them
}