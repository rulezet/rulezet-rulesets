rule TTP_XOR_QUAD_CurrentVersionRun_9dd2 {
  strings:
    $key_9dd2 = { ce bd [2] ea b3 [2] c1 9f [2] ef bd [2] fb a6 [2] f4 bc [2] ea a1 [2] e8 a0 [2] f3 a6 [2] ef a1 [2] f3 8e }

  condition:
    any of them
}