rule TTP_XOR_QUAD_CurrentVersionRun_9d26 {
  strings:
    $key_9d26 = { ce 49 [2] ea 47 [2] c1 6b [2] ef 49 [2] fb 52 [2] f4 48 [2] ea 55 [2] e8 54 [2] f3 52 [2] ef 55 [2] f3 7a }

  condition:
    any of them
}