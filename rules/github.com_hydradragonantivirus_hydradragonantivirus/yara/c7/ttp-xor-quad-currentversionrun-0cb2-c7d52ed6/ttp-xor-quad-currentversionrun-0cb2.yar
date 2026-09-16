rule TTP_XOR_QUAD_CurrentVersionRun_0cb2 {
  strings:
    $key_0cb2 = { 5f dd [2] 7b d3 [2] 50 ff [2] 7e dd [2] 6a c6 [2] 65 dc [2] 7b c1 [2] 79 c0 [2] 62 c6 [2] 7e c1 [2] 62 ee }

  condition:
    any of them
}