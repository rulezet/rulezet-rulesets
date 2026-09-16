rule TTP_XOR_QUAD_CurrentVersionRun_d5b6 {
  strings:
    $key_d5b6 = { 86 d9 [2] a2 d7 [2] 89 fb [2] a7 d9 [2] b3 c2 [2] bc d8 [2] a2 c5 [2] a0 c4 [2] bb c2 [2] a7 c5 [2] bb ea }

  condition:
    any of them
}