rule TTP_XOR_QUAD_CurrentVersionRun_9d33 {
  strings:
    $key_9d33 = { ce 5c [2] ea 52 [2] c1 7e [2] ef 5c [2] fb 47 [2] f4 5d [2] ea 40 [2] e8 41 [2] f3 47 [2] ef 40 [2] f3 6f }

  condition:
    any of them
}