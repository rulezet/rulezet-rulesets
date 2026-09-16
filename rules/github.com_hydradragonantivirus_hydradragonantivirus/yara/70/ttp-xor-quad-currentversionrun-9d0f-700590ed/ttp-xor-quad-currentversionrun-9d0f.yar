rule TTP_XOR_QUAD_CurrentVersionRun_9d0f {
  strings:
    $key_9d0f = { ce 60 [2] ea 6e [2] c1 42 [2] ef 60 [2] fb 7b [2] f4 61 [2] ea 7c [2] e8 7d [2] f3 7b [2] ef 7c [2] f3 53 }

  condition:
    any of them
}