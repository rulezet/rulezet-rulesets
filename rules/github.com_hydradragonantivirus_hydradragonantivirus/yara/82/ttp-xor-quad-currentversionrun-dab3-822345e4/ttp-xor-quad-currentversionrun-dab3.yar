rule TTP_XOR_QUAD_CurrentVersionRun_dab3 {
  strings:
    $key_dab3 = { 89 dc [2] ad d2 [2] 86 fe [2] a8 dc [2] bc c7 [2] b3 dd [2] ad c0 [2] af c1 [2] b4 c7 [2] a8 c0 [2] b4 ef }

  condition:
    any of them
}