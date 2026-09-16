rule TTP_XOR_QUAD_CurrentVersionRun_9db5 {
  strings:
    $key_9db5 = { ce da [2] ea d4 [2] c1 f8 [2] ef da [2] fb c1 [2] f4 db [2] ea c6 [2] e8 c7 [2] f3 c1 [2] ef c6 [2] f3 e9 }

  condition:
    any of them
}