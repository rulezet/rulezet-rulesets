rule TTP_XOR_QUAD_CurrentVersionRun_9d63 {
  strings:
    $key_9d63 = { ce 0c [2] ea 02 [2] c1 2e [2] ef 0c [2] fb 17 [2] f4 0d [2] ea 10 [2] e8 11 [2] f3 17 [2] ef 10 [2] f3 3f }

  condition:
    any of them
}