rule TTP_XOR_QUAD_CurrentVersionRun_9dc6 {
  strings:
    $key_9dc6 = { ce a9 [2] ea a7 [2] c1 8b [2] ef a9 [2] fb b2 [2] f4 a8 [2] ea b5 [2] e8 b4 [2] f3 b2 [2] ef b5 [2] f3 9a }

  condition:
    any of them
}