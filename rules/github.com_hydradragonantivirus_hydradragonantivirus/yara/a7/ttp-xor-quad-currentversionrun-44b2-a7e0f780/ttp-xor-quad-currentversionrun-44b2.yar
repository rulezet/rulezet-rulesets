rule TTP_XOR_QUAD_CurrentVersionRun_44b2 {
  strings:
    $key_44b2 = { 17 dd [2] 33 d3 [2] 18 ff [2] 36 dd [2] 22 c6 [2] 2d dc [2] 33 c1 [2] 31 c0 [2] 2a c6 [2] 36 c1 [2] 2a ee }

  condition:
    any of them
}