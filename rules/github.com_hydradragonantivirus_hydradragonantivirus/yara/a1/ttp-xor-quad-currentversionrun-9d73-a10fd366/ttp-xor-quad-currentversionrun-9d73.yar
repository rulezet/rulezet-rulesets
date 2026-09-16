rule TTP_XOR_QUAD_CurrentVersionRun_9d73 {
  strings:
    $key_9d73 = { ce 1c [2] ea 12 [2] c1 3e [2] ef 1c [2] fb 07 [2] f4 1d [2] ea 00 [2] e8 01 [2] f3 07 [2] ef 00 [2] f3 2f }

  condition:
    any of them
}