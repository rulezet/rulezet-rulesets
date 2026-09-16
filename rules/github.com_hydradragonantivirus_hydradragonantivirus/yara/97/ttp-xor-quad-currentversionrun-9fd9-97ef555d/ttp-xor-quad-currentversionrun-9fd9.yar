rule TTP_XOR_QUAD_CurrentVersionRun_9fd9 {
  strings:
    $key_9fd9 = { cc b6 [2] e8 b8 [2] c3 94 [2] ed b6 [2] f9 ad [2] f6 b7 [2] e8 aa [2] ea ab [2] f1 ad [2] ed aa [2] f1 85 }

  condition:
    any of them
}