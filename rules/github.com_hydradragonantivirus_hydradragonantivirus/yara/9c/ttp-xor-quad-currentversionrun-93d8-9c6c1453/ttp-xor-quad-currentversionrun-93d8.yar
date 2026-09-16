rule TTP_XOR_QUAD_CurrentVersionRun_93d8 {
  strings:
    $key_93d8 = { c0 b7 [2] e4 b9 [2] cf 95 [2] e1 b7 [2] f5 ac [2] fa b6 [2] e4 ab [2] e6 aa [2] fd ac [2] e1 ab [2] fd 84 }

  condition:
    any of them
}