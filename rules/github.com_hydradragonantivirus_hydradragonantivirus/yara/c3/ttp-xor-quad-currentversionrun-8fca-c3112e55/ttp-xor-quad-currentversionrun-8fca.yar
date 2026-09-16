rule TTP_XOR_QUAD_CurrentVersionRun_8fca {
  strings:
    $key_8fca = { dc a5 [2] f8 ab [2] d3 87 [2] fd a5 [2] e9 be [2] e6 a4 [2] f8 b9 [2] fa b8 [2] e1 be [2] fd b9 [2] e1 96 }

  condition:
    any of them
}