rule TTP_XOR_QUAD_CurrentVersionRun_9d74 {
  strings:
    $key_9d74 = { ce 1b [2] ea 15 [2] c1 39 [2] ef 1b [2] fb 00 [2] f4 1a [2] ea 07 [2] e8 06 [2] f3 00 [2] ef 07 [2] f3 28 }

  condition:
    any of them
}