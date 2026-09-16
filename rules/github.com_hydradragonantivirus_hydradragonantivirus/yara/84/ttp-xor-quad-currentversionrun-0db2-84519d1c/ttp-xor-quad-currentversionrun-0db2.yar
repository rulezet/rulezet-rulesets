rule TTP_XOR_QUAD_CurrentVersionRun_0db2 {
  strings:
    $key_0db2 = { 5e dd [2] 7a d3 [2] 51 ff [2] 7f dd [2] 6b c6 [2] 64 dc [2] 7a c1 [2] 78 c0 [2] 63 c6 [2] 7f c1 [2] 63 ee }

  condition:
    any of them
}