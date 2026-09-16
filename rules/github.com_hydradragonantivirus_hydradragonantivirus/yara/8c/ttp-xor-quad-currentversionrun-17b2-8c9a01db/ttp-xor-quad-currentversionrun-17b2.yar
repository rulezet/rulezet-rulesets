rule TTP_XOR_QUAD_CurrentVersionRun_17b2 {
  strings:
    $key_17b2 = { 44 dd [2] 60 d3 [2] 4b ff [2] 65 dd [2] 71 c6 [2] 7e dc [2] 60 c1 [2] 62 c0 [2] 79 c6 [2] 65 c1 [2] 79 ee }

  condition:
    any of them
}