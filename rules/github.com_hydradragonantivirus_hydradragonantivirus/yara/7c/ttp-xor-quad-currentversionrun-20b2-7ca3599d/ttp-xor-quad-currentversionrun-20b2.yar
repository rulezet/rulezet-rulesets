rule TTP_XOR_QUAD_CurrentVersionRun_20b2 {
  strings:
    $key_20b2 = { 73 dd [2] 57 d3 [2] 7c ff [2] 52 dd [2] 46 c6 [2] 49 dc [2] 57 c1 [2] 55 c0 [2] 4e c6 [2] 52 c1 [2] 4e ee }

  condition:
    any of them
}