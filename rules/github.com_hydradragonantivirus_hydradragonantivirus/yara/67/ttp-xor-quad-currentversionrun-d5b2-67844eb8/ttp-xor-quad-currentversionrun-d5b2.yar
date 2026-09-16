rule TTP_XOR_QUAD_CurrentVersionRun_d5b2 {
  strings:
    $key_d5b2 = { 86 dd [2] a2 d3 [2] 89 ff [2] a7 dd [2] b3 c6 [2] bc dc [2] a2 c1 [2] a0 c0 [2] bb c6 [2] a7 c1 [2] bb ee }

  condition:
    any of them
}