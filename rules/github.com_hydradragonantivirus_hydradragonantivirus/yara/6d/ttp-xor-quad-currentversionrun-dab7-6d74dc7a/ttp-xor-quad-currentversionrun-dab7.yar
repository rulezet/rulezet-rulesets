rule TTP_XOR_QUAD_CurrentVersionRun_dab7 {
  strings:
    $key_dab7 = { 89 d8 [2] ad d6 [2] 86 fa [2] a8 d8 [2] bc c3 [2] b3 d9 [2] ad c4 [2] af c5 [2] b4 c3 [2] a8 c4 [2] b4 eb }

  condition:
    any of them
}