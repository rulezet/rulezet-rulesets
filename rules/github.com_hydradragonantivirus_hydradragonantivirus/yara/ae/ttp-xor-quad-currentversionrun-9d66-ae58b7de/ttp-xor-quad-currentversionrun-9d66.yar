rule TTP_XOR_QUAD_CurrentVersionRun_9d66 {
  strings:
    $key_9d66 = { ce 09 [2] ea 07 [2] c1 2b [2] ef 09 [2] fb 12 [2] f4 08 [2] ea 15 [2] e8 14 [2] f3 12 [2] ef 15 [2] f3 3a }

  condition:
    any of them
}