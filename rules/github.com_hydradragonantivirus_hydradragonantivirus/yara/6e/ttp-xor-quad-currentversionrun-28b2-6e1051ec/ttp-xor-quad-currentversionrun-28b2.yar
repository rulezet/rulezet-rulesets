rule TTP_XOR_QUAD_CurrentVersionRun_28b2 {
  strings:
    $key_28b2 = { 7b dd [2] 5f d3 [2] 74 ff [2] 5a dd [2] 4e c6 [2] 41 dc [2] 5f c1 [2] 5d c0 [2] 46 c6 [2] 5a c1 [2] 46 ee }

  condition:
    any of them
}