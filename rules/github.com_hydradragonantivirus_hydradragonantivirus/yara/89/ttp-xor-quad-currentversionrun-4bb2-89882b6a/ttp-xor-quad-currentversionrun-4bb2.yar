rule TTP_XOR_QUAD_CurrentVersionRun_4bb2 {
  strings:
    $key_4bb2 = { 18 dd [2] 3c d3 [2] 17 ff [2] 39 dd [2] 2d c6 [2] 22 dc [2] 3c c1 [2] 3e c0 [2] 25 c6 [2] 39 c1 [2] 25 ee }

  condition:
    any of them
}