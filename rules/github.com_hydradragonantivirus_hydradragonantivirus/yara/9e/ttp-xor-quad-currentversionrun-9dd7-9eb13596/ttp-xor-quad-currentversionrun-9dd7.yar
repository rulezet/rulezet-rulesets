rule TTP_XOR_QUAD_CurrentVersionRun_9dd7 {
  strings:
    $key_9dd7 = { ce b8 [2] ea b6 [2] c1 9a [2] ef b8 [2] fb a3 [2] f4 b9 [2] ea a4 [2] e8 a5 [2] f3 a3 [2] ef a4 [2] f3 8b }

  condition:
    any of them
}