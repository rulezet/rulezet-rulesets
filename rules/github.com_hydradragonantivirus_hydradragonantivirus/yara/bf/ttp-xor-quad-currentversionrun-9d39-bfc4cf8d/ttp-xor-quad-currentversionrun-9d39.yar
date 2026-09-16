rule TTP_XOR_QUAD_CurrentVersionRun_9d39 {
  strings:
    $key_9d39 = { ce 56 [2] ea 58 [2] c1 74 [2] ef 56 [2] fb 4d [2] f4 57 [2] ea 4a [2] e8 4b [2] f3 4d [2] ef 4a [2] f3 65 }

  condition:
    any of them
}