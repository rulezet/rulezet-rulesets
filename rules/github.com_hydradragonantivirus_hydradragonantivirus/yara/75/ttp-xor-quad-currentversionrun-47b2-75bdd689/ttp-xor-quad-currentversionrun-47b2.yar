rule TTP_XOR_QUAD_CurrentVersionRun_47b2 {
  strings:
    $key_47b2 = { 14 dd [2] 30 d3 [2] 1b ff [2] 35 dd [2] 21 c6 [2] 2e dc [2] 30 c1 [2] 32 c0 [2] 29 c6 [2] 35 c1 [2] 29 ee }

  condition:
    any of them
}