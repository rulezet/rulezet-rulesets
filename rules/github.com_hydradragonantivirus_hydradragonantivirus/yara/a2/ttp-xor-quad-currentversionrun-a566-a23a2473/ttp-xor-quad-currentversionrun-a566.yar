rule TTP_XOR_QUAD_CurrentVersionRun_a566 {
  strings:
    $key_a566 = { f6 09 [2] d2 07 [2] f9 2b [2] d7 09 [2] c3 12 [2] cc 08 [2] d2 15 [2] d0 14 [2] cb 12 [2] d7 15 [2] cb 3a }

  condition:
    any of them
}