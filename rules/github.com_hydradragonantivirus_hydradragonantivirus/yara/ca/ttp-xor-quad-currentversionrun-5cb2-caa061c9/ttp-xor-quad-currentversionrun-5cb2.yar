rule TTP_XOR_QUAD_CurrentVersionRun_5cb2 {
  strings:
    $key_5cb2 = { 0f dd [2] 2b d3 [2] 00 ff [2] 2e dd [2] 3a c6 [2] 35 dc [2] 2b c1 [2] 29 c0 [2] 32 c6 [2] 2e c1 [2] 32 ee }

  condition:
    any of them
}