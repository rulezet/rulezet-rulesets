rule TTP_XOR_QUAD_CurrentVersionRun_9d0b {
  strings:
    $key_9d0b = { ce 64 [2] ea 6a [2] c1 46 [2] ef 64 [2] fb 7f [2] f4 65 [2] ea 78 [2] e8 79 [2] f3 7f [2] ef 78 [2] f3 57 }

  condition:
    any of them
}