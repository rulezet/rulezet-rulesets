rule TTP_XOR_QUAD_CurrentVersionRun_07b2 {
  strings:
    $key_07b2 = { 54 dd [2] 70 d3 [2] 5b ff [2] 75 dd [2] 61 c6 [2] 6e dc [2] 70 c1 [2] 72 c0 [2] 69 c6 [2] 75 c1 [2] 69 ee }

  condition:
    any of them
}