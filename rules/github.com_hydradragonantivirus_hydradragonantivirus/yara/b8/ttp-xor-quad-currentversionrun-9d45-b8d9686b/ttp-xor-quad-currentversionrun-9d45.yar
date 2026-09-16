rule TTP_XOR_QUAD_CurrentVersionRun_9d45 {
  strings:
    $key_9d45 = { ce 2a [2] ea 24 [2] c1 08 [2] ef 2a [2] fb 31 [2] f4 2b [2] ea 36 [2] e8 37 [2] f3 31 [2] ef 36 [2] f3 19 }

  condition:
    any of them
}