rule TTP_XOR_QUAD_CurrentVersionRun_c9b2 {
  strings:
    $key_c9b2 = { 9a dd [2] be d3 [2] 95 ff [2] bb dd [2] af c6 [2] a0 dc [2] be c1 [2] bc c0 [2] a7 c6 [2] bb c1 [2] a7 ee }

  condition:
    any of them
}