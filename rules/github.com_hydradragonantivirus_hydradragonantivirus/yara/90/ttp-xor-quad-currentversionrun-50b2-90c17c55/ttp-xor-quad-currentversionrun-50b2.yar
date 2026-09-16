rule TTP_XOR_QUAD_CurrentVersionRun_50b2 {
  strings:
    $key_50b2 = { 03 dd [2] 27 d3 [2] 0c ff [2] 22 dd [2] 36 c6 [2] 39 dc [2] 27 c1 [2] 25 c0 [2] 3e c6 [2] 22 c1 [2] 3e ee }

  condition:
    any of them
}