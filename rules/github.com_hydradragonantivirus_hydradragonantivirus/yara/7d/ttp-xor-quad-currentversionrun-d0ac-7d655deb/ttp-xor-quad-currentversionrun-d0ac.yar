rule TTP_XOR_QUAD_CurrentVersionRun_d0ac {
  strings:
    $key_d0ac = { 83 c3 [2] a7 cd [2] 8c e1 [2] a2 c3 [2] b6 d8 [2] b9 c2 [2] a7 df [2] a5 de [2] be d8 [2] a2 df [2] be f0 }

  condition:
    any of them
}