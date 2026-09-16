rule TTP_XOR_QUAD_CurrentVersionRun_9db3 {
  strings:
    $key_9db3 = { ce dc [2] ea d2 [2] c1 fe [2] ef dc [2] fb c7 [2] f4 dd [2] ea c0 [2] e8 c1 [2] f3 c7 [2] ef c0 [2] f3 ef }

  condition:
    any of them
}