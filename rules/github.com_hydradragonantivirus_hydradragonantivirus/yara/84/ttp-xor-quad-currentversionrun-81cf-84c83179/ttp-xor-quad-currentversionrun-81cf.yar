rule TTP_XOR_QUAD_CurrentVersionRun_81cf {
  strings:
    $key_81cf = { d2 a0 [2] f6 ae [2] dd 82 [2] f3 a0 [2] e7 bb [2] e8 a1 [2] f6 bc [2] f4 bd [2] ef bb [2] f3 bc [2] ef 93 }

  condition:
    any of them
}