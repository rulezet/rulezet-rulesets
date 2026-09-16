rule TTP_XOR_QUAD_CurrentVersionRun_a5d9 {
  strings:
    $key_a5d9 = { f6 b6 [2] d2 b8 [2] f9 94 [2] d7 b6 [2] c3 ad [2] cc b7 [2] d2 aa [2] d0 ab [2] cb ad [2] d7 aa [2] cb 85 }

  condition:
    any of them
}