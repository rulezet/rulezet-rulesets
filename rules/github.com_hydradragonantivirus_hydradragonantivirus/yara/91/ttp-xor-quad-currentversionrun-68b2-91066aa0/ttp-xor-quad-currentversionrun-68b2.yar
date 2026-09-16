rule TTP_XOR_QUAD_CurrentVersionRun_68b2 {
  strings:
    $key_68b2 = { 3b dd [2] 1f d3 [2] 34 ff [2] 1a dd [2] 0e c6 [2] 01 dc [2] 1f c1 [2] 1d c0 [2] 06 c6 [2] 1a c1 [2] 06 ee }

  condition:
    any of them
}