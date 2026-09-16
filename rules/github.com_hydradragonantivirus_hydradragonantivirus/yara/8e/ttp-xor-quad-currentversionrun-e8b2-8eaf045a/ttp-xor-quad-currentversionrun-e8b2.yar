rule TTP_XOR_QUAD_CurrentVersionRun_e8b2 {
  strings:
    $key_e8b2 = { bb dd [2] 9f d3 [2] b4 ff [2] 9a dd [2] 8e c6 [2] 81 dc [2] 9f c1 [2] 9d c0 [2] 86 c6 [2] 9a c1 [2] 86 ee }

  condition:
    any of them
}