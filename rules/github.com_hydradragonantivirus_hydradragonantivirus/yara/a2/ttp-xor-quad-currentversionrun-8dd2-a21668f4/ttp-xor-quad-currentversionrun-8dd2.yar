rule TTP_XOR_QUAD_CurrentVersionRun_8dd2 {
  strings:
    $key_8dd2 = { de bd [2] fa b3 [2] d1 9f [2] ff bd [2] eb a6 [2] e4 bc [2] fa a1 [2] f8 a0 [2] e3 a6 [2] ff a1 [2] e3 8e }

  condition:
    any of them
}