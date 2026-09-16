rule TTP_XOR_QUAD_CurrentVersionRun_e7b2 {
  strings:
    $key_e7b2 = { b4 dd [2] 90 d3 [2] bb ff [2] 95 dd [2] 81 c6 [2] 8e dc [2] 90 c1 [2] 92 c0 [2] 89 c6 [2] 95 c1 [2] 89 ee }

  condition:
    any of them
}