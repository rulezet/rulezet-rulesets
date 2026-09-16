rule TTP_XOR_QUAD_CurrentVersionRun_9d79 {
  strings:
    $key_9d79 = { ce 16 [2] ea 18 [2] c1 34 [2] ef 16 [2] fb 0d [2] f4 17 [2] ea 0a [2] e8 0b [2] f3 0d [2] ef 0a [2] f3 25 }

  condition:
    any of them
}