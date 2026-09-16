rule TTP_XOR_QUAD_CurrentVersionRun_9dec {
  strings:
    $key_9dec = { ce 83 [2] ea 8d [2] c1 a1 [2] ef 83 [2] fb 98 [2] f4 82 [2] ea 9f [2] e8 9e [2] f3 98 [2] ef 9f [2] f3 b0 }

  condition:
    any of them
}