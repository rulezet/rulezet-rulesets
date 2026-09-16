rule TTP_XOR_QUAD_CurrentVersionRun_9d77 {
  strings:
    $key_9d77 = { ce 18 [2] ea 16 [2] c1 3a [2] ef 18 [2] fb 03 [2] f4 19 [2] ea 04 [2] e8 05 [2] f3 03 [2] ef 04 [2] f3 2b }

  condition:
    any of them
}