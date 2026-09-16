rule TTP_XOR_QUAD_CurrentVersionRun_4fb2 {
  strings:
    $key_4fb2 = { 1c dd [2] 38 d3 [2] 13 ff [2] 3d dd [2] 29 c6 [2] 26 dc [2] 38 c1 [2] 3a c0 [2] 21 c6 [2] 3d c1 [2] 21 ee }

  condition:
    any of them
}