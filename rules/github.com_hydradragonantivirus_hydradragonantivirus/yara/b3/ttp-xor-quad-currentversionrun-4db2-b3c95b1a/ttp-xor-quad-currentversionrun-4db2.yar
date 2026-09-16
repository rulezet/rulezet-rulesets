rule TTP_XOR_QUAD_CurrentVersionRun_4db2 {
  strings:
    $key_4db2 = { 1e dd [2] 3a d3 [2] 11 ff [2] 3f dd [2] 2b c6 [2] 24 dc [2] 3a c1 [2] 38 c0 [2] 23 c6 [2] 3f c1 [2] 23 ee }

  condition:
    any of them
}