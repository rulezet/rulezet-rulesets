rule TTP_XOR_QUAD_CurrentVersionRun_8dd9 {
  strings:
    $key_8dd9 = { de b6 [2] fa b8 [2] d1 94 [2] ff b6 [2] eb ad [2] e4 b7 [2] fa aa [2] f8 ab [2] e3 ad [2] ff aa [2] e3 85 }

  condition:
    any of them
}