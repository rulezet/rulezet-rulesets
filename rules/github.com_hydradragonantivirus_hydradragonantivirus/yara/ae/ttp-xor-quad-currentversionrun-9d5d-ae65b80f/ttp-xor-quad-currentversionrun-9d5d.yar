rule TTP_XOR_QUAD_CurrentVersionRun_9d5d {
  strings:
    $key_9d5d = { ce 32 [2] ea 3c [2] c1 10 [2] ef 32 [2] fb 29 [2] f4 33 [2] ea 2e [2] e8 2f [2] f3 29 [2] ef 2e [2] f3 01 }

  condition:
    any of them
}