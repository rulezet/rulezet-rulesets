rule TTP_XOR_QUAD_CurrentVersionRun_9da3 {
  strings:
    $key_9da3 = { ce cc [2] ea c2 [2] c1 ee [2] ef cc [2] fb d7 [2] f4 cd [2] ea d0 [2] e8 d1 [2] f3 d7 [2] ef d0 [2] f3 ff }

  condition:
    any of them
}