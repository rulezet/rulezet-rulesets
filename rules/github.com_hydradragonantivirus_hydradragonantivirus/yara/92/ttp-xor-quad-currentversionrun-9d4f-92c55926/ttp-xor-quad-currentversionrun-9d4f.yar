rule TTP_XOR_QUAD_CurrentVersionRun_9d4f {
  strings:
    $key_9d4f = { ce 20 [2] ea 2e [2] c1 02 [2] ef 20 [2] fb 3b [2] f4 21 [2] ea 3c [2] e8 3d [2] f3 3b [2] ef 3c [2] f3 13 }

  condition:
    any of them
}