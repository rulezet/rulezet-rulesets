rule TTP_XOR_QUAD_CurrentVersionRun_9d2d {
  strings:
    $key_9d2d = { ce 42 [2] ea 4c [2] c1 60 [2] ef 42 [2] fb 59 [2] f4 43 [2] ea 5e [2] e8 5f [2] f3 59 [2] ef 5e [2] f3 71 }

  condition:
    any of them
}