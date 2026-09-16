rule TTP_XOR_QUAD_CurrentVersionRun_8fd5 {
  strings:
    $key_8fd5 = { dc ba [2] f8 b4 [2] d3 98 [2] fd ba [2] e9 a1 [2] e6 bb [2] f8 a6 [2] fa a7 [2] e1 a1 [2] fd a6 [2] e1 89 }

  condition:
    any of them
}