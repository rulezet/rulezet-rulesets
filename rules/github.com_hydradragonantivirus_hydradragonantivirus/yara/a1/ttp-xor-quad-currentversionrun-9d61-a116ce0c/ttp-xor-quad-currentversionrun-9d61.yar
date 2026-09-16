rule TTP_XOR_QUAD_CurrentVersionRun_9d61 {
  strings:
    $key_9d61 = { ce 0e [2] ea 00 [2] c1 2c [2] ef 0e [2] fb 15 [2] f4 0f [2] ea 12 [2] e8 13 [2] f3 15 [2] ef 12 [2] f3 3d }

  condition:
    any of them
}