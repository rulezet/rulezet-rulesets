rule TTP_XOR_QUAD_CurrentVersionRun_04ac {
  strings:
    $key_04ac = { 57 c3 [2] 73 cd [2] 58 e1 [2] 76 c3 [2] 62 d8 [2] 6d c2 [2] 73 df [2] 71 de [2] 6a d8 [2] 76 df [2] 6a f0 }

  condition:
    any of them
}