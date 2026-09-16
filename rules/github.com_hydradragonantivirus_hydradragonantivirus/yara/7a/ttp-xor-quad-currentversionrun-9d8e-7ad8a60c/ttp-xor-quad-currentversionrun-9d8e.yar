rule TTP_XOR_QUAD_CurrentVersionRun_9d8e {
  strings:
    $key_9d8e = { ce e1 [2] ea ef [2] c1 c3 [2] ef e1 [2] fb fa [2] f4 e0 [2] ea fd [2] e8 fc [2] f3 fa [2] ef fd [2] f3 d2 }

  condition:
    any of them
}