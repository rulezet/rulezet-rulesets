rule TTP_XOR_QUAD_CurrentVersionRun_e4ac {
  strings:
    $key_e4ac = { b7 c3 [2] 93 cd [2] b8 e1 [2] 96 c3 [2] 82 d8 [2] 8d c2 [2] 93 df [2] 91 de [2] 8a d8 [2] 96 df [2] 8a f0 }

  condition:
    any of them
}