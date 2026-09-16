rule TTP_XOR_QUAD_CurrentVersionRun_9d6b {
  strings:
    $key_9d6b = { ce 04 [2] ea 0a [2] c1 26 [2] ef 04 [2] fb 1f [2] f4 05 [2] ea 18 [2] e8 19 [2] f3 1f [2] ef 18 [2] f3 37 }

  condition:
    any of them
}