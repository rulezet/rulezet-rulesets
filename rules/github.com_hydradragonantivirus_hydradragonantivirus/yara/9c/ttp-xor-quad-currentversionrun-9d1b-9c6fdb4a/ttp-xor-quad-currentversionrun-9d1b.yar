rule TTP_XOR_QUAD_CurrentVersionRun_9d1b {
  strings:
    $key_9d1b = { ce 74 [2] ea 7a [2] c1 56 [2] ef 74 [2] fb 6f [2] f4 75 [2] ea 68 [2] e8 69 [2] f3 6f [2] ef 68 [2] f3 47 }

  condition:
    any of them
}