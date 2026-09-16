rule TTP_XOR_QUAD_CurrentVersionRun_74b2 {
  strings:
    $key_74b2 = { 27 dd [2] 03 d3 [2] 28 ff [2] 06 dd [2] 12 c6 [2] 1d dc [2] 03 c1 [2] 01 c0 [2] 1a c6 [2] 06 c1 [2] 1a ee }

  condition:
    any of them
}