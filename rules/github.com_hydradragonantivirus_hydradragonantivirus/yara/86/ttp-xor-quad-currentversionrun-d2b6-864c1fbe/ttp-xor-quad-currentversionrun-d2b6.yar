rule TTP_XOR_QUAD_CurrentVersionRun_d2b6 {
  strings:
    $key_d2b6 = { 81 d9 [2] a5 d7 [2] 8e fb [2] a0 d9 [2] b4 c2 [2] bb d8 [2] a5 c5 [2] a7 c4 [2] bc c2 [2] a0 c5 [2] bc ea }

  condition:
    any of them
}