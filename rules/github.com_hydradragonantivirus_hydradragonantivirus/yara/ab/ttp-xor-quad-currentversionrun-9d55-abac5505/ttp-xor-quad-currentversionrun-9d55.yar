rule TTP_XOR_QUAD_CurrentVersionRun_9d55 {
  strings:
    $key_9d55 = { ce 3a [2] ea 34 [2] c1 18 [2] ef 3a [2] fb 21 [2] f4 3b [2] ea 26 [2] e8 27 [2] f3 21 [2] ef 26 [2] f3 09 }

  condition:
    any of them
}