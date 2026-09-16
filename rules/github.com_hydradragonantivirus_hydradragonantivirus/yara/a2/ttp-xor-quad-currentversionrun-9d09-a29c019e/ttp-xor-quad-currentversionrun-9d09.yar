rule TTP_XOR_QUAD_CurrentVersionRun_9d09 {
  strings:
    $key_9d09 = { ce 66 [2] ea 68 [2] c1 44 [2] ef 66 [2] fb 7d [2] f4 67 [2] ea 7a [2] e8 7b [2] f3 7d [2] ef 7a [2] f3 55 }

  condition:
    any of them
}