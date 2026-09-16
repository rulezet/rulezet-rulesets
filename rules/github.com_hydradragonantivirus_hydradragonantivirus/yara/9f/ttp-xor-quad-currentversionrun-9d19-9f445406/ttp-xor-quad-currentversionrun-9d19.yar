rule TTP_XOR_QUAD_CurrentVersionRun_9d19 {
  strings:
    $key_9d19 = { ce 76 [2] ea 78 [2] c1 54 [2] ef 76 [2] fb 6d [2] f4 77 [2] ea 6a [2] e8 6b [2] f3 6d [2] ef 6a [2] f3 45 }

  condition:
    any of them
}