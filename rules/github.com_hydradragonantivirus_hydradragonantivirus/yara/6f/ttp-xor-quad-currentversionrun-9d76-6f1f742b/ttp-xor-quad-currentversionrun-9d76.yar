rule TTP_XOR_QUAD_CurrentVersionRun_9d76 {
  strings:
    $key_9d76 = { ce 19 [2] ea 17 [2] c1 3b [2] ef 19 [2] fb 02 [2] f4 18 [2] ea 05 [2] e8 04 [2] f3 02 [2] ef 05 [2] f3 2a }

  condition:
    any of them
}