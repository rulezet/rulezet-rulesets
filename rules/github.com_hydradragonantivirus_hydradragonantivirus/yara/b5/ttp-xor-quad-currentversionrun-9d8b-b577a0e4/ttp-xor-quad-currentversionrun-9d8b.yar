rule TTP_XOR_QUAD_CurrentVersionRun_9d8b {
  strings:
    $key_9d8b = { ce e4 [2] ea ea [2] c1 c6 [2] ef e4 [2] fb ff [2] f4 e5 [2] ea f8 [2] e8 f9 [2] f3 ff [2] ef f8 [2] f3 d7 }

  condition:
    any of them
}