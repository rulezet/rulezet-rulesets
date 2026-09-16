rule TTP_XOR_QUAD_CurrentVersionRun_49b2 {
  strings:
    $key_49b2 = { 1a dd [2] 3e d3 [2] 15 ff [2] 3b dd [2] 2f c6 [2] 20 dc [2] 3e c1 [2] 3c c0 [2] 27 c6 [2] 3b c1 [2] 27 ee }

  condition:
    any of them
}