rule TTP_XOR_QUAD_CurrentVersionRun_3fb2 {
  strings:
    $key_3fb2 = { 6c dd [2] 48 d3 [2] 63 ff [2] 4d dd [2] 59 c6 [2] 56 dc [2] 48 c1 [2] 4a c0 [2] 51 c6 [2] 4d c1 [2] 51 ee }

  condition:
    any of them
}