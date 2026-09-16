rule TTP_XOR_QUAD_CurrentVersionRun_9dc7 {
  strings:
    $key_9dc7 = { ce a8 [2] ea a6 [2] c1 8a [2] ef a8 [2] fb b3 [2] f4 a9 [2] ea b4 [2] e8 b5 [2] f3 b3 [2] ef b4 [2] f3 9b }

  condition:
    any of them
}