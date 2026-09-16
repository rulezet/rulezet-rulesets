rule TTP_XOR_QUAD_CurrentVersionRun_9d28 {
  strings:
    $key_9d28 = { ce 47 [2] ea 49 [2] c1 65 [2] ef 47 [2] fb 5c [2] f4 46 [2] ea 5b [2] e8 5a [2] f3 5c [2] ef 5b [2] f3 74 }

  condition:
    any of them
}