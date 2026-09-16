rule TTP_XOR_QUAD_CurrentVersionRun_9d64 {
  strings:
    $key_9d64 = { ce 0b [2] ea 05 [2] c1 29 [2] ef 0b [2] fb 10 [2] f4 0a [2] ea 17 [2] e8 16 [2] f3 10 [2] ef 17 [2] f3 38 }

  condition:
    any of them
}