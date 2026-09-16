rule TTP_XOR_QUAD_CurrentVersionRun_b0b2 {
  strings:
    $key_b0b2 = { e3 dd [2] c7 d3 [2] ec ff [2] c2 dd [2] d6 c6 [2] d9 dc [2] c7 c1 [2] c5 c0 [2] de c6 [2] c2 c1 [2] de ee }

  condition:
    any of them
}