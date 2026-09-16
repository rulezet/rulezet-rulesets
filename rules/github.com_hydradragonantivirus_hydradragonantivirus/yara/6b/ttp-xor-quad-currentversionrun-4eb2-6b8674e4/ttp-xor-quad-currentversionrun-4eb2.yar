rule TTP_XOR_QUAD_CurrentVersionRun_4eb2 {
  strings:
    $key_4eb2 = { 1d dd [2] 39 d3 [2] 12 ff [2] 3c dd [2] 28 c6 [2] 27 dc [2] 39 c1 [2] 3b c0 [2] 20 c6 [2] 3c c1 [2] 20 ee }

  condition:
    any of them
}