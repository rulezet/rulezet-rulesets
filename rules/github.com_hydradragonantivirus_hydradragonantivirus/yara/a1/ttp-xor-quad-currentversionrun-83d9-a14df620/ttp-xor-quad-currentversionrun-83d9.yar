rule TTP_XOR_QUAD_CurrentVersionRun_83d9 {
  strings:
    $key_83d9 = { d0 b6 [2] f4 b8 [2] df 94 [2] f1 b6 [2] e5 ad [2] ea b7 [2] f4 aa [2] f6 ab [2] ed ad [2] f1 aa [2] ed 85 }

  condition:
    any of them
}