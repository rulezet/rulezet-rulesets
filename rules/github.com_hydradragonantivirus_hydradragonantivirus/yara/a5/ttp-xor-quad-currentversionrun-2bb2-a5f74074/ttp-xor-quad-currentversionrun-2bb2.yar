rule TTP_XOR_QUAD_CurrentVersionRun_2bb2 {
  strings:
    $key_2bb2 = { 78 dd [2] 5c d3 [2] 77 ff [2] 59 dd [2] 4d c6 [2] 42 dc [2] 5c c1 [2] 5e c0 [2] 45 c6 [2] 59 c1 [2] 45 ee }

  condition:
    any of them
}