rule TTP_XOR_QUAD_CurrentVersionRun_42b2 {
  strings:
    $key_42b2 = { 11 dd [2] 35 d3 [2] 1e ff [2] 30 dd [2] 24 c6 [2] 2b dc [2] 35 c1 [2] 37 c0 [2] 2c c6 [2] 30 c1 [2] 2c ee }

  condition:
    any of them
}