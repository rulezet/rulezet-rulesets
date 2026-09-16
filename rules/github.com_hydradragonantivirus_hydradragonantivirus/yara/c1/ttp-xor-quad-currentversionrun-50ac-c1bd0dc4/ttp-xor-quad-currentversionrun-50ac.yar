rule TTP_XOR_QUAD_CurrentVersionRun_50ac {
  strings:
    $key_50ac = { 03 c3 [2] 27 cd [2] 0c e1 [2] 22 c3 [2] 36 d8 [2] 39 c2 [2] 27 df [2] 25 de [2] 3e d8 [2] 22 df [2] 3e f0 }

  condition:
    any of them
}