rule TTP_XOR_QUAD_CurrentVersionRun_11b2 {
  strings:
    $key_11b2 = { 42 dd [2] 66 d3 [2] 4d ff [2] 63 dd [2] 77 c6 [2] 78 dc [2] 66 c1 [2] 64 c0 [2] 7f c6 [2] 63 c1 [2] 7f ee }

  condition:
    any of them
}