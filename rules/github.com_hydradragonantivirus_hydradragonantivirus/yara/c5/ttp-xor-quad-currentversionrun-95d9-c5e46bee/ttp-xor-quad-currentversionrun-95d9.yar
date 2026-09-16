rule TTP_XOR_QUAD_CurrentVersionRun_95d9 {
  strings:
    $key_95d9 = { c6 b6 [2] e2 b8 [2] c9 94 [2] e7 b6 [2] f3 ad [2] fc b7 [2] e2 aa [2] e0 ab [2] fb ad [2] e7 aa [2] fb 85 }

  condition:
    any of them
}