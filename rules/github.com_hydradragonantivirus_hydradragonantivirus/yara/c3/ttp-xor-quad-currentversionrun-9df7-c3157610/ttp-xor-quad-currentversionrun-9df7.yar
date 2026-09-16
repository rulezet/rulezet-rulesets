rule TTP_XOR_QUAD_CurrentVersionRun_9df7 {
  strings:
    $key_9df7 = { ce 98 [2] ea 96 [2] c1 ba [2] ef 98 [2] fb 83 [2] f4 99 [2] ea 84 [2] e8 85 [2] f3 83 [2] ef 84 [2] f3 ab }

  condition:
    any of them
}