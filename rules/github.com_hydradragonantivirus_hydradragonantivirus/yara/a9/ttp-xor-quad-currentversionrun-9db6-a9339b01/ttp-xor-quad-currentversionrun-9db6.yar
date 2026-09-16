rule TTP_XOR_QUAD_CurrentVersionRun_9db6 {
  strings:
    $key_9db6 = { ce d9 [2] ea d7 [2] c1 fb [2] ef d9 [2] fb c2 [2] f4 d8 [2] ea c5 [2] e8 c4 [2] f3 c2 [2] ef c5 [2] f3 ea }

  condition:
    any of them
}