rule TTP_XOR_QUAD_CurrentVersionRun_8fd7 {
  strings:
    $key_8fd7 = { dc b8 [2] f8 b6 [2] d3 9a [2] fd b8 [2] e9 a3 [2] e6 b9 [2] f8 a4 [2] fa a5 [2] e1 a3 [2] fd a4 [2] e1 8b }

  condition:
    any of them
}