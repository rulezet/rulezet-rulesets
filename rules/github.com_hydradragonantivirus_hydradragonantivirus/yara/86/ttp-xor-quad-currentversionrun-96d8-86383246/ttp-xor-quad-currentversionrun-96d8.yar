rule TTP_XOR_QUAD_CurrentVersionRun_96d8 {
  strings:
    $key_96d8 = { c5 b7 [2] e1 b9 [2] ca 95 [2] e4 b7 [2] f0 ac [2] ff b6 [2] e1 ab [2] e3 aa [2] f8 ac [2] e4 ab [2] f8 84 }

  condition:
    any of them
}