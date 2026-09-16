rule TTP_XOR_QUAD_CurrentVersionRun_d5ac {
  strings:
    $key_d5ac = { 86 c3 [2] a2 cd [2] 89 e1 [2] a7 c3 [2] b3 d8 [2] bc c2 [2] a2 df [2] a0 de [2] bb d8 [2] a7 df [2] bb f0 }

  condition:
    any of them
}