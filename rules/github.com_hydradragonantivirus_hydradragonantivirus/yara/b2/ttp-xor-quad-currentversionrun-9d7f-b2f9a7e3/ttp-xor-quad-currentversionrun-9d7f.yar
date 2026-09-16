rule TTP_XOR_QUAD_CurrentVersionRun_9d7f {
  strings:
    $key_9d7f = { ce 10 [2] ea 1e [2] c1 32 [2] ef 10 [2] fb 0b [2] f4 11 [2] ea 0c [2] e8 0d [2] f3 0b [2] ef 0c [2] f3 23 }

  condition:
    any of them
}