rule TTP_XOR_QUAD_CurrentVersionRun_9d60 {
  strings:
    $key_9d60 = { ce 0f [2] ea 01 [2] c1 2d [2] ef 0f [2] fb 14 [2] f4 0e [2] ea 13 [2] e8 12 [2] f3 14 [2] ef 13 [2] f3 3c }

  condition:
    any of them
}