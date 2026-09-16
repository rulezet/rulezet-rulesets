rule TTP_XOR_QUAD_CurrentVersionRun_9d5f {
  strings:
    $key_9d5f = { ce 30 [2] ea 3e [2] c1 12 [2] ef 30 [2] fb 2b [2] f4 31 [2] ea 2c [2] e8 2d [2] f3 2b [2] ef 2c [2] f3 03 }

  condition:
    any of them
}