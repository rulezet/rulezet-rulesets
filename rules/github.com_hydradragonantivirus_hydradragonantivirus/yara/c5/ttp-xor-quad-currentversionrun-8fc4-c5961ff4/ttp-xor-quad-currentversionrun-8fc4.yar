rule TTP_XOR_QUAD_CurrentVersionRun_8fc4 {
  strings:
    $key_8fc4 = { dc ab [2] f8 a5 [2] d3 89 [2] fd ab [2] e9 b0 [2] e6 aa [2] f8 b7 [2] fa b6 [2] e1 b0 [2] fd b7 [2] e1 98 }

  condition:
    any of them
}