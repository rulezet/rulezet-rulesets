rule TTP_XOR_QUAD_CurrentVersionRun_acd9 {
  strings:
    $key_acd9 = { ff b6 [2] db b8 [2] f0 94 [2] de b6 [2] ca ad [2] c5 b7 [2] db aa [2] d9 ab [2] c2 ad [2] de aa [2] c2 85 }

  condition:
    any of them
}