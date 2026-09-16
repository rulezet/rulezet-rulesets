rule TTP_XOR_QUAD_CurrentVersionRun_84d9 {
  strings:
    $key_84d9 = { d7 b6 [2] f3 b8 [2] d8 94 [2] f6 b6 [2] e2 ad [2] ed b7 [2] f3 aa [2] f1 ab [2] ea ad [2] f6 aa [2] ea 85 }

  condition:
    any of them
}