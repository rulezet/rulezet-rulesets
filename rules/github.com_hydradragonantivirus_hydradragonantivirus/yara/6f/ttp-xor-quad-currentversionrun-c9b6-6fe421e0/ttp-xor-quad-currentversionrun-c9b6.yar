rule TTP_XOR_QUAD_CurrentVersionRun_c9b6 {
  strings:
    $key_c9b6 = { 9a d9 [2] be d7 [2] 95 fb [2] bb d9 [2] af c2 [2] a0 d8 [2] be c5 [2] bc c4 [2] a7 c2 [2] bb c5 [2] a7 ea }

  condition:
    any of them
}