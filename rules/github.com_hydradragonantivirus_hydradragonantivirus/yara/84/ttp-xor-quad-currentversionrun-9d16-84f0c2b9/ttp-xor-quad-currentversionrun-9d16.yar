rule TTP_XOR_QUAD_CurrentVersionRun_9d16 {
  strings:
    $key_9d16 = { ce 79 [2] ea 77 [2] c1 5b [2] ef 79 [2] fb 62 [2] f4 78 [2] ea 65 [2] e8 64 [2] f3 62 [2] ef 65 [2] f3 4a }

  condition:
    any of them
}