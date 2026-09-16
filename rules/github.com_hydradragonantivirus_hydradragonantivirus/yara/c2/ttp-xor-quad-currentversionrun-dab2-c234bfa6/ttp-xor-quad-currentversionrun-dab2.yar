rule TTP_XOR_QUAD_CurrentVersionRun_dab2 {
  strings:
    $key_dab2 = { 89 dd [2] ad d3 [2] 86 ff [2] a8 dd [2] bc c6 [2] b3 dc [2] ad c1 [2] af c0 [2] b4 c6 [2] a8 c1 [2] b4 ee }

  condition:
    any of them
}