rule TTP_XOR_QUAD_CurrentVersionRun_64b2 {
  strings:
    $key_64b2 = { 37 dd [2] 13 d3 [2] 38 ff [2] 16 dd [2] 02 c6 [2] 0d dc [2] 13 c1 [2] 11 c0 [2] 0a c6 [2] 16 c1 [2] 0a ee }

  condition:
    any of them
}