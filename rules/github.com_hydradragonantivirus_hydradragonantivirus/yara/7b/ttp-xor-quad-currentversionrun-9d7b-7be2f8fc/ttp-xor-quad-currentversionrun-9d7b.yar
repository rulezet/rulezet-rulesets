rule TTP_XOR_QUAD_CurrentVersionRun_9d7b {
  strings:
    $key_9d7b = { ce 14 [2] ea 1a [2] c1 36 [2] ef 14 [2] fb 0f [2] f4 15 [2] ea 08 [2] e8 09 [2] f3 0f [2] ef 08 [2] f3 27 }

  condition:
    any of them
}