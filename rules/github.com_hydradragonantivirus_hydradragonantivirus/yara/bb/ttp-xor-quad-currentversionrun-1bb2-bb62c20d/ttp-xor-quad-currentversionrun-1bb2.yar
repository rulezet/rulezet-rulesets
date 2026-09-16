rule TTP_XOR_QUAD_CurrentVersionRun_1bb2 {
  strings:
    $key_1bb2 = { 48 dd [2] 6c d3 [2] 47 ff [2] 69 dd [2] 7d c6 [2] 72 dc [2] 6c c1 [2] 6e c0 [2] 75 c6 [2] 69 c1 [2] 75 ee }

  condition:
    any of them
}