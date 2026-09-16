rule TTP_XOR_QUAD_CurrentVersionRun_9d65 {
  strings:
    $key_9d65 = { ce 0a [2] ea 04 [2] c1 28 [2] ef 0a [2] fb 11 [2] f4 0b [2] ea 16 [2] e8 17 [2] f3 11 [2] ef 16 [2] f3 39 }

  condition:
    any of them
}