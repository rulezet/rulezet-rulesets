rule TTP_XOR_QUAD_CurrentVersionRun_a7b2 {
  strings:
    $key_a7b2 = { f4 dd [2] d0 d3 [2] fb ff [2] d5 dd [2] c1 c6 [2] ce dc [2] d0 c1 [2] d2 c0 [2] c9 c6 [2] d5 c1 [2] c9 ee }

  condition:
    any of them
}