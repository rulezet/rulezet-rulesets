rule TTP_XOR_QUAD_CurrentVersionRun_19b2 {
  strings:
    $key_19b2 = { 4a dd [2] 6e d3 [2] 45 ff [2] 6b dd [2] 7f c6 [2] 70 dc [2] 6e c1 [2] 6c c0 [2] 77 c6 [2] 6b c1 [2] 77 ee }

  condition:
    any of them
}