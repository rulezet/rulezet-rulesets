rule TTP_XOR_QUAD_CurrentVersionRun_9df3 {
  strings:
    $key_9df3 = { ce 9c [2] ea 92 [2] c1 be [2] ef 9c [2] fb 87 [2] f4 9d [2] ea 80 [2] e8 81 [2] f3 87 [2] ef 80 [2] f3 af }

  condition:
    any of them
}