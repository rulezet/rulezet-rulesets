rule TTP_XOR_QUAD_CurrentVersionRun_8fd8 {
  strings:
    $key_8fd8 = { dc b7 [2] f8 b9 [2] d3 95 [2] fd b7 [2] e9 ac [2] e6 b6 [2] f8 ab [2] fa aa [2] e1 ac [2] fd ab [2] e1 84 }

  condition:
    any of them
}