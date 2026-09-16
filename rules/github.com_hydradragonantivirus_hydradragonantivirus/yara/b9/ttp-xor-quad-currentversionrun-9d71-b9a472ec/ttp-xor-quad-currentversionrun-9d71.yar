rule TTP_XOR_QUAD_CurrentVersionRun_9d71 {
  strings:
    $key_9d71 = { ce 1e [2] ea 10 [2] c1 3c [2] ef 1e [2] fb 05 [2] f4 1f [2] ea 02 [2] e8 03 [2] f3 05 [2] ef 02 [2] f3 2d }

  condition:
    any of them
}