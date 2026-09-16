rule TTP_XOR_QUAD_CurrentVersionRun_9dc8 {
  strings:
    $key_9dc8 = { ce a7 [2] ea a9 [2] c1 85 [2] ef a7 [2] fb bc [2] f4 a6 [2] ea bb [2] e8 ba [2] f3 bc [2] ef bb [2] f3 94 }

  condition:
    any of them
}