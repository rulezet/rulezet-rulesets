rule TTP_XOR_QUAD_CurrentVersionRun_9d7c {
  strings:
    $key_9d7c = { ce 13 [2] ea 1d [2] c1 31 [2] ef 13 [2] fb 08 [2] f4 12 [2] ea 0f [2] e8 0e [2] f3 08 [2] ef 0f [2] f3 20 }

  condition:
    any of them
}