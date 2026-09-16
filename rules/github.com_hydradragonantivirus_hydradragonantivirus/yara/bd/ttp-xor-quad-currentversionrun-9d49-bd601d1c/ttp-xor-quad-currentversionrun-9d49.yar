rule TTP_XOR_QUAD_CurrentVersionRun_9d49 {
  strings:
    $key_9d49 = { ce 26 [2] ea 28 [2] c1 04 [2] ef 26 [2] fb 3d [2] f4 27 [2] ea 3a [2] e8 3b [2] f3 3d [2] ef 3a [2] f3 15 }

  condition:
    any of them
}