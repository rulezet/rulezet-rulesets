rule TTP_XOR_QUAD_CurrentVersionRun_9db4 {
  strings:
    $key_9db4 = { ce db [2] ea d5 [2] c1 f9 [2] ef db [2] fb c0 [2] f4 da [2] ea c7 [2] e8 c6 [2] f3 c0 [2] ef c7 [2] f3 e8 }

  condition:
    any of them
}