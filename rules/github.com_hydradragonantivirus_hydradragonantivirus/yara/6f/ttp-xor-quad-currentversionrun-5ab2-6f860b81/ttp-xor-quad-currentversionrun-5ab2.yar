rule TTP_XOR_QUAD_CurrentVersionRun_5ab2 {
  strings:
    $key_5ab2 = { 09 dd [2] 2d d3 [2] 06 ff [2] 28 dd [2] 3c c6 [2] 33 dc [2] 2d c1 [2] 2f c0 [2] 34 c6 [2] 28 c1 [2] 34 ee }

  condition:
    any of them
}