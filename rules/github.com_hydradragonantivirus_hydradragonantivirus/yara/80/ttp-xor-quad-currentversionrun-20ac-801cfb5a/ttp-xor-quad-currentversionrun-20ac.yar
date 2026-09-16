rule TTP_XOR_QUAD_CurrentVersionRun_20ac {
  strings:
    $key_20ac = { 73 c3 [2] 57 cd [2] 7c e1 [2] 52 c3 [2] 46 d8 [2] 49 c2 [2] 57 df [2] 55 de [2] 4e d8 [2] 52 df [2] 4e f0 }

  condition:
    any of them
}