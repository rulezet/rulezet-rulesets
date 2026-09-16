rule TTP_XOR_QUAD_CurrentVersionRun_9dfa {
  strings:
    $key_9dfa = { ce 95 [2] ea 9b [2] c1 b7 [2] ef 95 [2] fb 8e [2] f4 94 [2] ea 89 [2] e8 88 [2] f3 8e [2] ef 89 [2] f3 a6 }

  condition:
    any of them
}