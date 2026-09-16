rule TTP_XOR_QUAD_CurrentVersionRun_1cb2 {
  strings:
    $key_1cb2 = { 4f dd [2] 6b d3 [2] 40 ff [2] 6e dd [2] 7a c6 [2] 75 dc [2] 6b c1 [2] 69 c0 [2] 72 c6 [2] 6e c1 [2] 72 ee }

  condition:
    any of them
}