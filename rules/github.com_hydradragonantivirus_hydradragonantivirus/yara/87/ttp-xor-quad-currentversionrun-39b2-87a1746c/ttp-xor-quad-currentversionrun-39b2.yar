rule TTP_XOR_QUAD_CurrentVersionRun_39b2 {
  strings:
    $key_39b2 = { 6a dd [2] 4e d3 [2] 65 ff [2] 4b dd [2] 5f c6 [2] 50 dc [2] 4e c1 [2] 4c c0 [2] 57 c6 [2] 4b c1 [2] 57 ee }

  condition:
    any of them
}