rule TTP_XOR_QUAD_CurrentVersionRun_40b2 {
  strings:
    $key_40b2 = { 13 dd [2] 37 d3 [2] 1c ff [2] 32 dd [2] 26 c6 [2] 29 dc [2] 37 c1 [2] 35 c0 [2] 2e c6 [2] 32 c1 [2] 2e ee }

  condition:
    any of them
}