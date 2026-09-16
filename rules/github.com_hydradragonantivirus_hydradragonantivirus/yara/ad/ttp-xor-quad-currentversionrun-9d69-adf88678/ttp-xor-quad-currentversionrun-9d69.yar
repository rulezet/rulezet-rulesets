rule TTP_XOR_QUAD_CurrentVersionRun_9d69 {
  strings:
    $key_9d69 = { ce 06 [2] ea 08 [2] c1 24 [2] ef 06 [2] fb 1d [2] f4 07 [2] ea 1a [2] e8 1b [2] f3 1d [2] ef 1a [2] f3 35 }

  condition:
    any of them
}