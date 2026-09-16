rule TTP_XOR_QUAD_CurrentVersionRun_9d00 {
  strings:
    $key_9d00 = { ce 6f [2] ea 61 [2] c1 4d [2] ef 6f [2] fb 74 [2] f4 6e [2] ea 73 [2] e8 72 [2] f3 74 [2] ef 73 [2] f3 5c }

  condition:
    any of them
}