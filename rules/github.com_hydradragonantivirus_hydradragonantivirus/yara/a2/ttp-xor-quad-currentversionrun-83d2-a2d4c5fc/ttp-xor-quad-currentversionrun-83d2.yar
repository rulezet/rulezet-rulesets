rule TTP_XOR_QUAD_CurrentVersionRun_83d2 {
  strings:
    $key_83d2 = { d0 bd [2] f4 b3 [2] df 9f [2] f1 bd [2] e5 a6 [2] ea bc [2] f4 a1 [2] f6 a0 [2] ed a6 [2] f1 a1 [2] ed 8e }

  condition:
    any of them
}