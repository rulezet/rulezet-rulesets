rule TTP_XOR_QUAD_CurrentVersionRun_9d25 {
  strings:
    $key_9d25 = { ce 4a [2] ea 44 [2] c1 68 [2] ef 4a [2] fb 51 [2] f4 4b [2] ea 56 [2] e8 57 [2] f3 51 [2] ef 56 [2] f3 79 }

  condition:
    any of them
}