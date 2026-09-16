rule TTP_XOR_QUAD_CurrentVersionRun_dab6 {
  strings:
    $key_dab6 = { 89 d9 [2] ad d7 [2] 86 fb [2] a8 d9 [2] bc c2 [2] b3 d8 [2] ad c5 [2] af c4 [2] b4 c2 [2] a8 c5 [2] b4 ea }

  condition:
    any of them
}