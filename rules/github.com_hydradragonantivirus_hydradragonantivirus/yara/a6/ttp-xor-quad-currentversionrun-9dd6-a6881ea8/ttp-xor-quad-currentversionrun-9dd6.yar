rule TTP_XOR_QUAD_CurrentVersionRun_9dd6 {
  strings:
    $key_9dd6 = { ce b9 [2] ea b7 [2] c1 9b [2] ef b9 [2] fb a2 [2] f4 b8 [2] ea a5 [2] e8 a4 [2] f3 a2 [2] ef a5 [2] f3 8a }

  condition:
    any of them
}