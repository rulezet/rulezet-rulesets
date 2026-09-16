rule TTP_XOR_QUAD_CurrentVersionRun_9d5e {
  strings:
    $key_9d5e = { ce 31 [2] ea 3f [2] c1 13 [2] ef 31 [2] fb 2a [2] f4 30 [2] ea 2d [2] e8 2c [2] f3 2a [2] ef 2d [2] f3 02 }

  condition:
    any of them
}