rule TTP_XOR_QUAD_CurrentVersionRun_96d9 {
  strings:
    $key_96d9 = { c5 b6 [2] e1 b8 [2] ca 94 [2] e4 b6 [2] f0 ad [2] ff b7 [2] e1 aa [2] e3 ab [2] f8 ad [2] e4 aa [2] f8 85 }

  condition:
    any of them
}