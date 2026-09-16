rule TTP_XOR_QUAD_CurrentVersionRun_5db2 {
  strings:
    $key_5db2 = { 0e dd [2] 2a d3 [2] 01 ff [2] 2f dd [2] 3b c6 [2] 34 dc [2] 2a c1 [2] 28 c0 [2] 33 c6 [2] 2f c1 [2] 33 ee }

  condition:
    any of them
}