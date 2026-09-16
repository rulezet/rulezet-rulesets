rule TTP_XOR_QUAD_CurrentVersionRun_9db2 {
  strings:
    $key_9db2 = { ce dd [2] ea d3 [2] c1 ff [2] ef dd [2] fb c6 [2] f4 dc [2] ea c1 [2] e8 c0 [2] f3 c6 [2] ef c1 [2] f3 ee }

  condition:
    any of them
}