rule TTP_XOR_QUAD_CurrentVersionRun_8fc0 {
  strings:
    $key_8fc0 = { dc af [2] f8 a1 [2] d3 8d [2] fd af [2] e9 b4 [2] e6 ae [2] f8 b3 [2] fa b2 [2] e1 b4 [2] fd b3 [2] e1 9c }

  condition:
    any of them
}