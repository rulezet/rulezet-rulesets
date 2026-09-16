rule TTP_XOR_QUAD_CurrentVersionRun_d5ab {
  strings:
    $key_d5ab = { 86 c4 [2] a2 ca [2] 89 e6 [2] a7 c4 [2] b3 df [2] bc c5 [2] a2 d8 [2] a0 d9 [2] bb df [2] a7 d8 [2] bb f7 }

  condition:
    any of them
}