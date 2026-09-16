rule TTP_XOR_QUAD_CurrentVersionRun_7db2 {
  strings:
    $key_7db2 = { 2e dd [2] 0a d3 [2] 21 ff [2] 0f dd [2] 1b c6 [2] 14 dc [2] 0a c1 [2] 08 c0 [2] 13 c6 [2] 0f c1 [2] 13 ee }

  condition:
    any of them
}