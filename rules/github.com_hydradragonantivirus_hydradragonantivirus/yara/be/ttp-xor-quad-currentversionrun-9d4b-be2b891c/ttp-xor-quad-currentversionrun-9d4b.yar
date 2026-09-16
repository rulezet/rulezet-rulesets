rule TTP_XOR_QUAD_CurrentVersionRun_9d4b {
  strings:
    $key_9d4b = { ce 24 [2] ea 2a [2] c1 06 [2] ef 24 [2] fb 3f [2] f4 25 [2] ea 38 [2] e8 39 [2] f3 3f [2] ef 38 [2] f3 17 }

  condition:
    any of them
}