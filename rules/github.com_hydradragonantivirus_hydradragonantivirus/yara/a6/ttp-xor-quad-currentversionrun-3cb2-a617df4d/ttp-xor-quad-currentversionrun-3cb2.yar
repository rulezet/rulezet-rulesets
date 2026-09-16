rule TTP_XOR_QUAD_CurrentVersionRun_3cb2 {
  strings:
    $key_3cb2 = { 6f dd [2] 4b d3 [2] 60 ff [2] 4e dd [2] 5a c6 [2] 55 dc [2] 4b c1 [2] 49 c0 [2] 52 c6 [2] 4e c1 [2] 52 ee }

  condition:
    any of them
}