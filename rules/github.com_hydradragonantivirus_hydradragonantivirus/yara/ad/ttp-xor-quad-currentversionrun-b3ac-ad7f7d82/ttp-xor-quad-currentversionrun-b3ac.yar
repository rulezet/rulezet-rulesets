rule TTP_XOR_QUAD_CurrentVersionRun_b3ac {
  strings:
    $key_b3ac = { e0 c3 [2] c4 cd [2] ef e1 [2] c1 c3 [2] d5 d8 [2] da c2 [2] c4 df [2] c6 de [2] dd d8 [2] c1 df [2] dd f0 }

  condition:
    any of them
}