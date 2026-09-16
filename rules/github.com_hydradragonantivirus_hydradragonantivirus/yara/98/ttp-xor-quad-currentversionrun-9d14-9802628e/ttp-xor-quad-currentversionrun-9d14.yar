rule TTP_XOR_QUAD_CurrentVersionRun_9d14 {
  strings:
    $key_9d14 = { ce 7b [2] ea 75 [2] c1 59 [2] ef 7b [2] fb 60 [2] f4 7a [2] ea 67 [2] e8 66 [2] f3 60 [2] ef 67 [2] f3 48 }

  condition:
    any of them
}