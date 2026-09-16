rule TTP_XOR_QUAD_CurrentVersionRun_7fb2 {
  strings:
    $key_7fb2 = { 2c dd [2] 08 d3 [2] 23 ff [2] 0d dd [2] 19 c6 [2] 16 dc [2] 08 c1 [2] 0a c0 [2] 11 c6 [2] 0d c1 [2] 11 ee }

  condition:
    any of them
}