rule TTP_XOR_QUAD_CurrentVersionRun_69b2 {
  strings:
    $key_69b2 = { 3a dd [2] 1e d3 [2] 35 ff [2] 1b dd [2] 0f c6 [2] 00 dc [2] 1e c1 [2] 1c c0 [2] 07 c6 [2] 1b c1 [2] 07 ee }

  condition:
    any of them
}