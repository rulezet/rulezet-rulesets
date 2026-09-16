rule TTP_XOR_QUAD_CurrentVersionRun_9ded {
  strings:
    $key_9ded = { ce 82 [2] ea 8c [2] c1 a0 [2] ef 82 [2] fb 99 [2] f4 83 [2] ea 9e [2] e8 9f [2] f3 99 [2] ef 9e [2] f3 b1 }

  condition:
    any of them
}