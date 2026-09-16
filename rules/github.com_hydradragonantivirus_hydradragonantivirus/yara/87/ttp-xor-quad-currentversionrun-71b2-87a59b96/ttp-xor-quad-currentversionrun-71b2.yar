rule TTP_XOR_QUAD_CurrentVersionRun_71b2 {
  strings:
    $key_71b2 = { 22 dd [2] 06 d3 [2] 2d ff [2] 03 dd [2] 17 c6 [2] 18 dc [2] 06 c1 [2] 04 c0 [2] 1f c6 [2] 03 c1 [2] 1f ee }

  condition:
    any of them
}