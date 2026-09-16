rule TTP_XOR_QUAD_CurrentVersionRun_f8b2 {
  strings:
    $key_f8b2 = { ab dd [2] 8f d3 [2] a4 ff [2] 8a dd [2] 9e c6 [2] 91 dc [2] 8f c1 [2] 8d c0 [2] 96 c6 [2] 8a c1 [2] 96 ee }

  condition:
    any of them
}