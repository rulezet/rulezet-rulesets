rule TTP_XOR_QUAD_CurrentVersionRun_9d37 {
  strings:
    $key_9d37 = { ce 58 [2] ea 56 [2] c1 7a [2] ef 58 [2] fb 43 [2] f4 59 [2] ea 44 [2] e8 45 [2] f3 43 [2] ef 44 [2] f3 6b }

  condition:
    any of them
}