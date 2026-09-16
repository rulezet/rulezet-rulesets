rule TTP_XOR_QUAD_CurrentVersionRun_9ac6 {
  strings:
    $key_9ac6 = { c9 a9 [2] ed a7 [2] c6 8b [2] e8 a9 [2] fc b2 [2] f3 a8 [2] ed b5 [2] ef b4 [2] f4 b2 [2] e8 b5 [2] f4 9a }

  condition:
    any of them
}