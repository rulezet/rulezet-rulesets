rule TTP_XOR_QUAD_CurrentVersionRun_8fc2 {
  strings:
    $key_8fc2 = { dc ad [2] f8 a3 [2] d3 8f [2] fd ad [2] e9 b6 [2] e6 ac [2] f8 b1 [2] fa b0 [2] e1 b6 [2] fd b1 [2] e1 9e }

  condition:
    any of them
}