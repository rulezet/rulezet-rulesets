rule TTP_XOR_QUAD_CurrentVersionRun_9d15 {
  strings:
    $key_9d15 = { ce 7a [2] ea 74 [2] c1 58 [2] ef 7a [2] fb 61 [2] f4 7b [2] ea 66 [2] e8 67 [2] f3 61 [2] ef 66 [2] f3 49 }

  condition:
    any of them
}